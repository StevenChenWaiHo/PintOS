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
  void *upage;
  enum page_location location;
  bool writable;
  struct hash_elem spt_elem;
  struct file *file;
  size_t swap_slot;
  bool swapped;
  off_t ofs;
  uint32_t rbytes, zbytes;
  uint32_t *pd;
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

#endif