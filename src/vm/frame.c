#include <hash.h>
#include <threads/malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/spt.h"
#include "userprog/pagedir.h"
#include "devices/swap.h"
#include "userprog/syscall.h"

static struct list snd_chance;

struct hash ft;
struct lock ft_lock;

static unsigned int ft_entry_hash(const struct hash_elem *, void *UNUSED);
static bool ft_entry_comp(const struct hash_elem *, const struct hash_elem *, void *UNUSED);
void evict_filesys(void *upage, struct spt_entry *entry, uint32_t *pd);
void evict_mmap(struct spt_entry *entry, uint32_t *pd);
void evict_stack(void *upage, struct spt_entry *entry, uint32_t *pd);
void swap_page(void *upage, struct spt_entry *entry, uint32_t *pd);

/* Initialises frame table (ft). */
void
ft_init(void)
{
  list_init(&snd_chance);
  hash_init(&ft, ft_entry_hash, ft_entry_comp, NULL);
  lock_init(&ft_lock);
}

/* Get ft. */
struct hash *
get_ft(void)
{
  return &ft;
}

/* Acquires the lock for fts. */
void
ft_access_lock(void)
{
  lock_acquire(&ft_lock);
}


/* Releases the lock for fts. */
void
ft_access_unlock(void)
{
  lock_release(&ft_lock);
}

/* Evicts a filesys page. */
void
evict_filesys(void *kpage, struct spt_entry *entry, uint32_t *pd)
{
  if (entry->writable
    && pagedir_is_dirty (pd, entry->upage))
  {
    swap_page(kpage, entry, pd);
  }
  else
  {
    pagedir_clear_page(pd, entry->upage);
  }
}

/* Evicts a mmap page. */
void
evict_mmap(struct spt_entry *entry, uint32_t *pd)
{
  filesys_lock ();
  mm_file_write(entry->file, entry->rbytes, entry->upage, entry->ofs, pd);
  filesys_unlock ();
}

/* Evicts a stack page. */
void
evict_stack(void *kpage, struct spt_entry *entry, uint32_t *pd)
{
  swap_page(kpage, entry, pd);
}

/* Swaps KPAGE to swap disk. */
void
swap_page(void *kpage, struct spt_entry *entry, uint32_t *pd)
{
  pagedir_clear_page(pd, entry->upage);
  entry->swap_slot = swap_out(kpage);
  if (entry->swap_slot == -1) {
    /* Swap disk is full. */
    exit_handler (ERROR);
  }
  entry->swapped = true;
}

/* Returns the frame allocated to UPAGE. */
void *
get_frame(enum palloc_flags flag, void *upage, struct file *file)
{
  ft_access_lock();
  void *kpage = palloc_get_page(flag);

  if (kpage == NULL)
  {
    struct ft_entry *cur_ft = list_entry(list_pop_front(&snd_chance), struct ft_entry, ele_elem);
    ASSERT(cur_ft);
    while (true)
    {
      if (!cur_ft->pinned)
      {
        void *cur_upage = cur_ft->upage;
        struct spt_entry *cur_spt = spt_thread_lookup(cur_upage, cur_ft->t);
        if (cur_spt == NULL)
        {
          printf ("Cannot allocate cur_spt\n");
        }
        if (pagedir_is_accessed(cur_ft->t->pagedir, cur_upage))
        {
          pagedir_set_accessed(cur_ft->t->pagedir, cur_upage, false);
        }
        else
        {
          switch (cur_spt->location)
          {
          case FILE_SYS:
            evict_filesys(cur_ft->kpage, cur_spt, cur_ft->t->pagedir);
            break;

          case MMAP:
            evict_mmap(cur_spt, cur_ft->t->pagedir);
            break;

          case STACK:
            evict_stack(cur_ft->kpage, cur_spt, cur_ft->t->pagedir);
            break;

          default:
            ft_access_unlock();
            PANIC("Page stored in unknown location");
            break;
          }
          break;
        }
      }
      list_push_back(&snd_chance, &cur_ft->ele_elem);
      cur_ft = list_entry (list_pop_front (&snd_chance), struct ft_entry, ele_elem);
    }
    palloc_free_page (cur_ft->kpage);
    kpage = palloc_get_page (flag);
    ASSERT (kpage);
  }
  struct ft_entry *entry = (struct ft_entry *)malloc(sizeof(struct ft_entry));
  if (!entry)
  {
    ft_access_unlock();
    return NULL;
  }
  entry->kpage = kpage;
  entry->upage = upage;
  entry->file = file;
  entry->pinned = false;
  entry->t = thread_current ();
  list_push_back(&snd_chance, &entry->ele_elem);
  
  hash_insert(&ft, &entry->ft_elem);
  ft_access_unlock();
  return kpage;
}

/*hash find finds the hash element based on an entry's UPAGE address*/
struct ft_entry *
ft_search_entry(void *upage)
{
  struct ft_entry dummy;
  dummy.upage = upage;
  struct hash_elem *e = hash_find(&ft, &dummy.ft_elem);
  if (!e)
  {
    return NULL;
  }
  return hash_entry(e, struct ft_entry, ft_elem);
}

/*hash find finds the hash element based on the thread that owns a page */
struct ft_entry *
ft_search_frame_with_owner(struct thread *t)
{
    /* iterate through frame table to find a match */
    struct hash_iterator i;
    hash_first (&i, &ft);
    while (hash_next (&i))
    {
        struct ft_entry *f = hash_entry (hash_cur (&i), struct ft_entry, ft_elem);
        struct list_elem *e = list_begin (&f->owners);
        while (e != list_end (&f->owners))
        {
            struct owner *owner = list_entry(e, struct owner, owner_elem);
            if (owner->process == t)
            {
              return f;                  
            }
            e = list_next(e);
        }  
    }
    return NULL;
}

/* Remove second chance entries of this exiting thread. */
void
ft_free (struct thread *t) {
  if (!list_empty (&snd_chance)) {
    struct list_elem *e = list_front (&snd_chance);
    while (e != list_end (&snd_chance)) {
      struct ft_entry *snd_entry = list_entry (e, struct ft_entry, ele_elem);
      e = list_next (e);
      if (snd_entry->t == t) {
        list_remove (&snd_entry->ele_elem);
      }
    }
  }
}

/* Removes ft_entry from ft and frees ft_entry for UPAGE. */
void free_frame(void *upage)
{
  struct ft_entry *entry = ft_search_entry(upage);
  if (entry == NULL)
  {
    printf ("Cannot allocate entry\n");
    return;
  }
  hash_delete(&ft, &entry->ft_elem);
  palloc_free_page(entry->kpage);
  free(entry);
}

/* Adds ENTRY to ft. */
void ft_add_page_entry(struct ft_entry *entry)
{
  hash_insert(&ft, &entry->ft_elem);
}

/* Compares the upages in A and B. */
static bool
ft_entry_comp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  void *a_address = hash_entry(a, struct ft_entry, ft_elem)->upage;
  void *b_address = hash_entry(b, struct ft_entry, ft_elem)->upage;
  return a_address < b_address;
}

/* Hash function: entry hashed by the upage address */
static unsigned int
ft_entry_hash(const struct hash_elem *a, void *aux UNUSED)
{
  const struct ft_entry *e = hash_entry(a, struct ft_entry, ft_elem);
  return hash_bytes(&e->upage, sizeof(e->upage));
}