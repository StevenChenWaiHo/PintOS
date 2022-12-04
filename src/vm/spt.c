#include "vm/spt.h"
#include <hash.h>
#include <stdio.h>
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

unsigned spt_hash (const struct hash_elem *, void *);
bool spt_less (const struct hash_elem *, 
                      const struct hash_elem *,
                      void *);
static struct hash *cur_spt (void);
static void spt_destroy_single (struct hash_elem *, void *);
static void zero_from (void *, int);
static bool read_segment_from_file (struct spt_entry *, void *);

bool
spt_init (struct thread *t) {
  return hash_init (&t->spt, spt_hash, spt_less, NULL);
}

bool
spt_insert (struct spt_entry *entry) {
  struct hash_elem *e = hash_replace (cur_spt(), &entry->spt_elem);
  if (e) {
    struct spt_entry *replaced = hash_entry (e, struct spt_entry, spt_elem);
    free (replaced);
  }
  return e != NULL;
}

/* Search for spt_entry with upage as key,
  return NULL if not found. */
struct spt_entry *
spt_lookup (void *upage) {
  struct spt_entry dummy;
  dummy.upage = upage;
  struct hash_elem *e;
  e = hash_find (cur_spt(), &dummy.spt_elem);
  return e == NULL ? NULL : hash_entry (e, struct spt_entry, spt_elem);
}

bool
spt_remove (void *upage) {
  struct spt_entry dummy;
  dummy.upage = upage;
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
  //Do something when freeing all
}

void
spt_destroy () {
  hash_destroy (cur_spt(), spt_destroy_single);
}

bool
spt_pf_handler (void *fault_addr, struct intr_frame *f) {
  void *fault_page = pg_round_down (fault_addr);

  //printf("\n\nexception: fault addr: %p\n", fault_addr);
  /*
  if (ft_search_entry(aligned_fault_page)) {
    printf("spt_pf_handler: frame entry for this upage exists.\n");
  }
  */
  //printf("##### pagedir is %p\n", pagedir_get_page(thread_current()->pagedir, aligned_fault_page));
  struct spt_entry *entry = spt_lookup (fault_page);
  /*
  printf("spt_pf: upage = %p;  ", fault_page);
  if (entry)
    printf(entry->writable? "w\n" : "n/w\n");
  else
    printf("no entry.\n");
  */
  /* Determine cause. */
  bool not_present = (f->error_code & PF_P) == 0;
  bool write = (f->error_code & PF_W) != 0;
  bool user = (f->error_code & PF_U) != 0;

  if (entry == NULL || is_kernel_vaddr (fault_addr) || !not_present
    || (write && !entry->writable)) {
    /*
    if (entry == NULL) {
      printf("Can't find entry.\n");
    }
    if (is_kernel_vaddr (fault_addr)) {
      printf("Access kernel addr.\n");
    }
    if (!not_present) {
      printf("Writing r/o page.\n");
    }
    if (write && !entry->writable) {
      printf("Write to FILESYS r-o page.\n");
    }
    if (user) {
      printf("User fault!\n");
    } else {
      printf("Kernel fault!\n");
    }
    */
    return false;
  } else {
    /*allocate frame if frame not previously allocated.*/
    void *frame_pt = get_frame (PAL_USER, entry->upage);
    //printf("frame kpage: %p\n", frame_pt); 
    if (frame_pt == NULL) {
      //printf("Dying due to frame.\n");
      return false;
    } else {
      if (entry->location == FILE_SYS) {
        // Lazy loading..
        /* Either zero-out page,
          or fetch the data into the frame from the file,
          then point PTE to the frame. */
        if (entry->zbytes == PGSIZE) {
          zero_from (frame_pt, PGSIZE);
        } else if (!read_segment_from_file (entry, frame_pt)) {
          //printf("Dying due to read to file.\n");
          return false;
        }
        /**
         * only when upage is not mapped
         * (ie. NOT loading into prev page) do we call pagedir_set_page()
         * otherwise (ie. loading into prev page) 
         **/
        if (!pagedir_set_page (
            thread_current()->pagedir, fault_page, frame_pt, entry->writable)) {
          //printf("Dying due to setpage.\n");
          return false;
        }
      }
      if (entry->location == SWAP) {
        //Takes information in swap disk thru swap_in
      }
    }
  }
  //printf("---------LAZY LOADING COMPLETE---------\n\n");
  return true;
}

static void
zero_from (void *from, int size) {
  memset (from, 0, PGSIZE);
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