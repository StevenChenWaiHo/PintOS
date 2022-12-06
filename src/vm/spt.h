#ifndef SP_TABLE_H
#define SP_TABLE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

enum page_location
{
  FILE_SYS,
  STACK,
  SWAP
};

struct spt_entry
{
  void *upage;
  enum page_location location;
  bool writable;
  struct hash_elem spt_elem;
  struct file *file;
  off_t ofs;
  uint32_t rbytes, zbytes;
  // struct ft_entry frame;
};

bool spt_init (struct thread *);
bool spt_insert (struct spt_entry *);
struct spt_entry *spt_lookup (void *);
bool spt_remove (void *);
void spt_destroy (void);

bool spt_pf_handler (void *, bool, bool, bool, void *);

#endif