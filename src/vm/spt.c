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

static struct hash *spt_current (void);
static void spt_destroy_single (struct hash_elem *, void *);
unsigned spt_hash (const struct hash_elem *, void *);
bool spt_less (const struct hash_elem *, const struct hash_elem *, void *);
static bool grow_stack(void *);
static void zero_from (void *, int);
static bool read_segment_from_file (struct spt_entry *, void *);

/* Initialises the supplemental page table (spt) of thread T. */
bool
spt_init (struct thread *t) {
  lock_init (&sptlock);
  return hash_init (&t->spt, spt_hash, spt_less, NULL);
}
/* Returns the spt of the current thread. */
static struct hash *spt_current () {
  return &thread_current()->spt;
}

/* Acquires the lock for spts. */
void
spt_lock () {
  lock_acquire (&sptlock);
}

/* Releases the lock for spts. */
void
spt_unlock () {
  lock_release (&sptlock);
}

/* Inserts an spt_entry ENTRY into the spt of the current thread. */
bool
spt_insert (struct spt_entry *entry) {
  entry->swapped = false;
  entry->swap_slot = 0;
  entry->upage = pg_round_down (entry->upage);
  struct hash_elem *e = hash_replace (spt_current(), &entry->spt_elem);
  if (e) {
    struct spt_entry *replaced = hash_entry (e, struct spt_entry, spt_elem);
    free (replaced);
  }
  return e != NULL;
}

/* Searches for an spt_entry with the key UPAGE in the spt of the current thread,
   returns NULL if not found. */
struct spt_entry *
spt_lookup (void *upage) {
  return spt_thread_lookup (upage, thread_current ());
}

/* Searches for an spt_entry with the key UPAGE in the spt of the thread T,
   returns NULL if not found. */
struct spt_entry *
spt_thread_lookup (void *upage, struct thread *t) {
  struct spt_entry dummy;
  dummy.upage = pg_round_down (upage);
  struct hash_elem *e;
  e = hash_find (&t->spt, &dummy.spt_elem);
  return e == NULL ? NULL : hash_entry (e, struct spt_entry, spt_elem);
}

/* Removes the spt_entry with the key UPAGE from the spt of the current thread. */
bool
spt_remove (void *upage) {
  struct spt_entry dummy;
  dummy.upage = pg_round_down (upage);
  struct hash_elem *e = hash_delete (spt_current(), &dummy.spt_elem);
  if (e) {
    free (hash_entry (e, struct spt_entry, spt_elem));
  }
  return e != NULL;
}

/* Destroys the spt of the current thread. */
void
spt_destroy () {
  hash_destroy (spt_current(), spt_destroy_single);
}

/* Destroys the spt of the current thread. */
static void
spt_destroy_single (struct hash_elem *e, void *aux UNUSED) {
  struct spt_entry *entry = hash_entry (e, struct spt_entry, spt_elem);
  /* Free any swap space stuff here... */
  if (entry->swapped){
    swap_drop(entry->swap_slot);
  }
  free (entry);
}

/* Hashes the upage at E. */
unsigned
spt_hash (const struct hash_elem *e, void *aux UNUSED) {
  const struct spt_entry *entry = hash_entry (e, struct spt_entry, spt_elem);
  return hash_int (entry->upage);
}

/* Compares the upages in A and B. */
bool
spt_less (const struct hash_elem *a, const struct hash_elem *b,
          void *aux UNUSED) {
  const struct spt_entry *a_entry = hash_entry (a, struct spt_entry, spt_elem);
  const struct spt_entry *b_entry = hash_entry (b, struct spt_entry, spt_elem);
  return a_entry->upage < b_entry->upage;
}

/* Lazy loads UPAGE. (Assume page present.) */
bool
lazy_load (struct file *file, off_t ofs, uint8_t *upage,
          uint32_t read_bytes, uint32_t zero_bytes, bool writable,
          enum page_location location) {

  while (read_bytes > 0 || zero_bytes > 0) 
  {
      /**
      * SHARING: IMPLEMENTATION COMMENTED OUT, FOR YOUR REFERENCE
      * if page is read only:
      * look up share table to find FRAME with same FILE and PAGE NO
      * if frame exists:
      *   i. insert into share table the PAGE of FILE
      *   ii. copy KPAGE of the shared frame to KPAGE of PAGEDIR of thread_current()
      
        *********** CODE SEGMENT ***********
        if (!writable)
        {
          ft_access_lock();
          struct ft_entry *fte = st_find_frame_for_upage(upage, file);
          if (fte != NULL)
          {
            ft_access_unlock();
            return share_page(upage, fte, writable);
          }
          else {
            ft_access_unlock();
          }   
        }
        
        *********** SHARING DONE *********** 
      */
      
      /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    
    /* New load_segment with lazy loading. */
    struct spt_entry *entry = spt_lookup (upage);
    /* Checks if entry is in the spt of the current thread. */
    if (!entry) {
      /* Entry not present, creates and inserts upage. */
      entry = (struct spt_entry *) malloc (sizeof (struct spt_entry));
      if (entry == NULL) {
        printf("Cannot allocate entry\n");
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
      /* Entry present, updates SPT meta-data (load_segment). */
      if (page_read_bytes != entry->rbytes) {
        uint32_t old_rb = entry->rbytes;
        uint32_t old_zb = entry->zbytes;
        entry->rbytes = page_read_bytes;
        entry->zbytes = page_zero_bytes;
      }
      if (writable)
        entry->writable = writable;
    }
    /* Advance to the next page to be loaded. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    ofs += PGSIZE;
  }
  return true;
}

/* Grows the stack and installs the page at FAULT_ADDR if needed. */
bool
spt_pf_handler (void *fault_addr, bool not_present, bool write, bool user, void *esp) {
  void *fault_page = pg_round_down (fault_addr);
  struct spt_entry *entry = spt_lookup (fault_page);
  
  if (!entry) {
    /* Check if stack growth is needed. */ 
    if (esp == NULL || fault_addr == NULL || is_kernel_vaddr (fault_addr)
      || is_below_ustack (fault_addr) || esp - fault_addr > STACK_OFS
      || (PHYS_BASE - (int) fault_page) > STACK_MAX) { 
      return false;
    }
    return grow_stack (fault_page);
  } else {
    /* Write to read-only page. */
    if ((write && !entry->writable)) {
      return false;
    }

    /** SHARING: 
     * If uaddr is in share table, install page from there
     
      *********** CODE SEGMENT ***********

      if (!entry->writable)
        {
          ft_access_lock();
          struct ft_entry *fte = st_find_frame_for_upage(entry->upage, entry->file);
          if (fte)
          {
            ft_access_unlock();
            return share_page(fault_page, fte, entry->writable);
          }else {
          }
          ft_access_unlock();
        }
      *********** SHARING DONE ***********
    */ 

    /* Allocate frame if frame not previously allocated. */
    void *frame_pt = get_frame (PAL_USER, entry->upage, entry->file);
    if (frame_pt == NULL) {
      printf("Cannot get frame_pt\n");
      return false;
    } else {
      /* Checks if the spt_entry has been swapped. */
      //Swapping takes place first before checking location
      if (entry->swapped) {
        /* Gets page from the swap disk. */
        swap_in(frame_pt, entry->swap_slot);
        entry->swapped = false;
        if (!install_page (fault_page, frame_pt, entry->writable)) {
          return false;
        }
        pagedir_set_dirty(thread_current()->pagedir, fault_page, true);
      } else if (entry->location == FILE_SYS || entry->location == MMAP) {
        // Lazy loading..
        /* Either zero-out page,
          or fetch the data into the frame from the file,
          then point PTE to the frame. */
        if (entry->zbytes == PGSIZE) {
          zero_from (frame_pt, PGSIZE);
        } else if (!read_segment_from_file (entry, frame_pt)) {
          return false;
        }

        /* Installs the page. */
        if (!install_page (fault_page, frame_pt, entry->writable)) {
          return false;
        }

        /** SHARING: IMPLEMENTATION COMMENTED OUT, FOR YOUR REFERENCE
         * If new frame is read-only, add entry to share table
        
          *********** CODE SEGMENT ***********
          if (!entry->writable)
          {
          ft_access_lock();
          st_access_lock();
          struct ft_entry *ft_entry = ft_search_entry(fault_page);
          bool inserted = st_insert_share_entry(entry->file, entry->upage, ft_entry);
          ASSERT(inserted);
          ft_access_unlock();
          st_access_unlock();
          }
          *********** SHARING DONE ***********
        */
        
      }
    }
  }
  return true;
}

/* Insert an spt_entry on the stack into the spt of the current thread. */
void
insert_stack_entry (void *upage) {
  struct spt_entry *entry = (struct spt_entry *) malloc (sizeof (struct spt_entry));
  if (entry == NULL)
  {
    printf ("Cannot allocate entry\n");
    return;
  }
  entry->upage = upage;
  entry->location = STACK;
  entry->writable = true;
  spt_insert (entry);
}

/* Install and insert UPAGE into the stack. */
static bool
grow_stack(void *upage) {
  insert_stack_entry (upage);
  void* kpage = get_frame (PAL_USER | PAL_ZERO, upage, NULL);
  ASSERT(kpage);
  return install_page(upage, kpage, true);
}

/* Zero out SIZE bytes in memory starting at FROM. */
static void
zero_from (void *from, int size) {
  memset (from, 0, size);
}

/* Reads segment in the file of ENTRY into FRAME_PT. */
static bool
read_segment_from_file (struct spt_entry *entry, void *frame_pt) {
  filesys_lock ();
  file_seek (entry->file, entry->ofs);
  bool read_success = 
    entry->rbytes == (uint32_t) file_read (entry->file, frame_pt, entry->rbytes);
  zero_from (frame_pt + entry->rbytes, entry->zbytes);
  filesys_unlock ();
  return read_success;
}