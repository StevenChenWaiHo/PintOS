#ifndef SP_TABLE_H
#define SP_TABLE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

#define STACK_OFS 32
#define STACK_MAX PGSIZE * 2000            /* Default limit 8MB. */

enum page_location
{
  FILE_SYS,
  MMAP,
  STACK,
};

struct spt_entry
{
  void *upage;                  /* Virtual address of the entry*/
  enum page_location location;  /* Location of the page. */
  bool writable;                /* Read or write boolean. */
  struct hash_elem spt_elem;    /* Hash element for supplemental page table. */
  struct file *file;            /* If location is FILE_SYS or MMAP, 
                                    stores the referencing file. */
  size_t swap_slot;             /* If location is SWAP, stores the referencing
                                    swap slot. */
  bool swapped;                 /* Indicating if the entry is swapped. */
  off_t ofs;                    /* File offset the page is reading/writing in.*/
  uint32_t rbytes, zbytes;      /* The bytes that are needed to be read/write in
                                    or zeroed when referencing the file.*/
  uint32_t *pd;                 /* The corresponding page directory that this
                                    entry is accessing. */
};

bool spt_init (struct thread *);
void spt_lock (void);
void spt_unlock (void);
bool spt_insert (struct spt_entry *);
struct spt_entry *spt_lookup (void *);
struct spt_entry *spt_thread_lookup (void *, struct thread *);
bool spt_remove (void *);
void spt_destroy (void);

bool lazy_load (struct file *, off_t, uint8_t *,
  uint32_t, uint32_t, bool, enum page_location);
bool spt_pf_handler (void *, bool, bool, bool, void *);

void insert_stack_entry (void *);

#endif /* vm/spt.h */