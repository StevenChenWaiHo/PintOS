#include "vm/spt.h"
#include <hash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "devices/swap.h"
#include "filesys/file.h"
#include "userprog/exception.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/pte.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/share.h"

struct lock sptlock;

unsigned spt_hash (const struct hash_elem *, void *);
bool spt_less (const struct hash_elem *, 
                      const struct hash_elem *,
                      void *);
static struct hash *cur_spt (void);
static void spt_destroy_single (struct hash_elem *, void *);
static bool grow_stack(void *);
static void zero_from (void *, int);
static bool read_segment_from_file (struct spt_entry *, void *);

bool
spt_init (struct thread *t) {
  lock_init (&sptlock);
  return hash_init (&t->spt, spt_hash, spt_less, NULL);
}

void
spt_lock () {
  lock_acquire (&sptlock);
}

void
spt_unlock () {
  lock_release (&sptlock);
}

bool
spt_insert (struct spt_entry *entry) {
  entry->swapped = false;
  entry->swap_slot = 0;
  entry->upage = pg_round_down (entry->upage);
  struct hash_elem *e = hash_replace (cur_spt(), &entry->spt_elem);
  if (e) {
    printf("replaced sth???");
    struct spt_entry *replaced = hash_entry (e, struct spt_entry, spt_elem);
    free (replaced);
  }
  return e != NULL;
}

/* Search for spt_entry with upage as key,
  return NULL if not found. */
struct spt_entry *
spt_lookup (void *upage) {
  return spt_thread_lookup (upage, thread_current ());
}

struct spt_entry *
spt_thread_lookup (void *upage, struct thread *t) {
  struct spt_entry dummy;
  dummy.upage = pg_round_down (upage);
  struct hash_elem *e;
  e = hash_find (&t->spt, &dummy.spt_elem);
  return e == NULL ? NULL : hash_entry (e, struct spt_entry, spt_elem);
}

bool
spt_remove (void *upage) {
  struct spt_entry dummy;
  dummy.upage = pg_round_down (upage);
  struct hash_elem *e = hash_delete (cur_spt(), &dummy.spt_elem);
  if (e) {
    //Possibly freeing any memory allocated to spt_entry variables...
    //spt_destroy_single?
    free (hash_entry (e, struct spt_entry, spt_elem));
  }
  return e != NULL;
}

static void
spt_destroy_single (struct hash_elem *e, void *aux UNUSED) {
  struct spt_entry *entry = hash_entry (e, struct spt_entry, spt_elem);
  /* Free any swap space stuff here... */
  if (entry->swapped){
    swap_drop(entry->swap_slot);
  }
  free (entry);
}

void
spt_destroy () {
  hash_destroy (cur_spt(), spt_destroy_single);
}

/* Assume page present. */
bool
lazy_load (struct file *file, off_t ofs, uint8_t *upage,
          uint32_t read_bytes, uint32_t zero_bytes, bool writable,
          enum page_location location) {
  /*
  //if (location == MMAP) {
    printf("loading ");
    printf(writable? "w " : "n/w ");
    printf("segment at ofs %d to upage %p,\n", ofs, upage);
    printf("reading in %d and zeroing %d bytes...\n\n", read_bytes, zero_bytes);
  //}
  */
  while (read_bytes > 0 || zero_bytes > 0) 
  {
    /**
      * SHARING:
      * if page is read only:
      * look up share table to find FRAME with same FILE and PAGE NO
      * if frame exists:
      *   i. insert into share table the PAGE of FILE
      *   ii. copy KPAGE of the shared frame to KPAGE of PAGEDIR of thread_current()
      

      if (!writable)
      {
        //printf(writable? "w\n" : "n/w\n");
        struct ft_entry *fte = st_find_frame_for_upage(upage, file);
        if (fte)
        {
          bool inserted = st_insert_share_entry(file, upage, fte);
          bool success = install_page(upage, fte->kernel_page, writable);
          //printf((inserted && success)? "sharing successful\n" : "sharing unsuccessful\n");
        } else
        {
          //printf("share table no such frame\n");
        }
      }
      */
      /* *********** SHARING DONE *********** */

    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    
    /* New load_segment with lazy loading. */
    struct spt_entry *entry = spt_lookup (upage);
    if (!entry) {
      //printf("load seg: creating entry for %p\n", upage);
      // No previous entries in SPT, creates one and insert after assign args
      entry = (struct spt_entry *) malloc (sizeof (struct spt_entry));
      if (entry == NULL) {
        return false;
      }
      entry->location = location;
      entry->file = file;
      entry->ofs = ofs;
      entry->rbytes = page_read_bytes;
      entry->zbytes = page_zero_bytes;
      entry->upage = upage;
      entry->writable = writable;
      spt_insert (entry);
    } else {
      // Previous entry present, update SPT meta-data (load_segment).
      //printf("Previous entry present, update SPT meta-data.\n");
      if (page_read_bytes != entry->rbytes) {
        uint32_t old_rb = entry->rbytes;
        uint32_t old_zb = entry->zbytes;
        entry->rbytes = page_read_bytes;
        entry->zbytes = page_zero_bytes;
        //printf("rb old vs new: %u: %u\n", old_rb, entry->rbytes);
        //printf("zb old vs new: %u: %u\n", old_zb, entry->zbytes);
      }
      if (writable)
        entry->writable = writable;
    }
    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    ofs += PGSIZE;
  }
  return true;
}

bool
spt_pf_handler (void *fault_addr, bool not_present, bool write, bool user, void *esp) {
  void *fault_page = pg_round_down (fault_addr);
  struct spt_entry *entry = spt_lookup (fault_page);
  
  if (!entry) {
    /* Check if needs stack growth. */ 
    if (esp == NULL) {
      return false;
    }
    if (fault_addr == NULL || is_kernel_vaddr (fault_addr)
      || is_below_ustack (fault_addr) || esp - fault_addr > STACK_OFS
      || (PHYS_BASE - (int) fault_page) > STACK_MAX) { 
        //printf("Tid : %d, fault_addr = %p", thread_current ()->tid, fault_addr);
      return false;
    }
    return grow_stack (fault_page);
  } else {
    /* Write to read-only page. */
    if ((write && !entry->writable)) {
      return false;
    } 
    /* Allocate frame if frame not previously allocated. */
    void *frame_pt = get_frame (PAL_USER, entry->upage, entry->file);
    if (frame_pt == NULL) {
      return false;
    } else {
      //Swapping takes place first before checking location
      if (entry->swapped) {
        //Takes information in swap disk thru swap_in
        swap_in(frame_pt, entry->swap_slot);
        entry->swapped = false;
        //printf("Swapping in page at %p, w? %d\n", fault_page, entry->writable);
        if (!install_page (fault_page, frame_pt, entry->writable)) {
          return false;
        }
        pagedir_set_dirty(thread_current()->pagedir, fault_page, true);
      } else if (entry->location == FILE_SYS || entry->location == MMAP) {
        // Lazy loading..
        /* Either zero-out page,
          or fetch the data into the frame from the file,
          then point PTE to the frame. */
        //printf("Loading in page at %p, w? %d\n", fault_page, entry->writable);
        if (entry->zbytes == PGSIZE) {
          zero_from (frame_pt, PGSIZE);
        } else if (!read_segment_from_file (entry, frame_pt)) {
          return false;
        }
        /**
         * only when upage is not mapped
         * (ie. NOT loading into prev page) do we call pagedir_set_page()
         * otherwise (ie. loading into prev page)
         * ^ This can be done by install_page() 
         **/
        if (!install_page (fault_page, frame_pt, entry->writable)) {
          return false;
        }
        
        /** SHARING: 
         * If new frame is read-only, add entry to share table
        
        if (!entry->writable)
        {
          // printf("spt_pf_handler:: ofs: %d, file: %p, upage %p\n", entry->ofs, entry->file, entry->upage);
          struct ft_entry *ft_entry = ft_search_entry(frame_pt);
          // printf((ft_entry != NULL)? "frame successfully fetched\n" : "frame unsuccessfully fetched\n");
          bool inserted = st_insert_share_entry(entry->file, entry->upage, ft_entry);
          // printf(inserted? "new sharing entry inserted successfully\n" : "new sharing entry inserted UNsuccessfully\n");
          ASSERT(inserted);
        }
        */
        /* *********** SHARING DONE *********** */
      }
    }
  }
  //printf("---------LAZY LOADING COMPLETE---------\n\n");
  return true;
}

static bool
grow_stack(void *upage) {
  struct spt_entry *entry = (struct spt_entry *) malloc (sizeof (struct spt_entry));
  entry->upage = upage;
  entry->location = STACK;
  entry->writable = true;
  spt_insert (entry);
  void* kpage = get_frame (PAL_USER | PAL_ZERO, upage, NULL);
  if (kpage != NULL && !install_page(upage, kpage, true))
  {
    return false;
  }
  return true;
}

static void
zero_from (void *from, int size) {
  memset (from, 0, size);
}

static bool
read_segment_from_file (struct spt_entry *entry, void *frame_pt) {
  //Fetch data into the frame.
  filesys_lock ();
  file_seek (entry->file, entry->ofs);
  bool read_success = 
    entry->rbytes == (uint32_t) file_read (entry->file, frame_pt, entry->rbytes);
  zero_from (frame_pt + entry->rbytes, entry->zbytes);
  filesys_unlock ();
  return read_success;
}

static struct hash *cur_spt () {
  return &thread_current()->spt;
}

unsigned
spt_hash (const struct hash_elem *e, void *aux UNUSED) {
  const struct spt_entry *entry = hash_entry (e, struct spt_entry, spt_elem);
  return hash_int (entry->upage);
}

bool
spt_less (const struct hash_elem *a, const struct hash_elem *b,
          void *aux UNUSED) {
  const struct spt_entry *a_entry = hash_entry (a, struct spt_entry, spt_elem);
  const struct spt_entry *b_entry = hash_entry (b, struct spt_entry, spt_elem);
  return a_entry->upage < b_entry->upage;
}