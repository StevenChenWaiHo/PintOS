#ifndef SP_TABLE_H
#define SP_TABLE_H

#include <stdbool.h>
#include "lib/kernel/hash.h"
#include "threads/thread.h"

enum page_location
{
  FILESYS,
  SWAP,
  ZERO
};

struct spt_entry
{
  void *upage;
  enum page_location location;
  bool writable;
  struct hash_elem spt_elem;
  struct file *file;
  
  // struct ft_entry frame;
};

bool spt_init (void);
bool spt_insert (struct spt_entry *);
struct spt_entry *spt_lookup (void *);
void spt_destroy ();

#endif