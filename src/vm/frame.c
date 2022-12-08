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

/* EVICT: Declare snd_chance list and its pointer. */
static struct list snd_chance;

struct hash ft;
struct lock ft_lock;

static bool ft_entry_comp(const struct hash_elem *, const struct hash_elem *, void *UNUSED);
static unsigned int ft_entry_hash(const struct hash_elem *, void *UNUSED);
void swap_page(void *upage, struct spt_entry *entry);
void evict_filesys(void *upage, struct spt_entry *entry);
void evict_mmap(void *upage, struct spt_entry *entry);
void evict_stack(void *upage, struct spt_entry *entry);

void ft_init(void)
{
  /* EVICT: Init snd_chance list. */
  list_init(&snd_chance);
  hash_init(&ft, ft_entry_hash, ft_entry_comp, NULL);
  lock_init(&ft_lock);
}

struct hash *
get_ft(void)
{
  return &ft;
}

void ft_access_lock(void)
{
  lock_acquire(&ft_lock);
}

void ft_access_unlock(void)
{
  lock_release(&ft_lock);
}

/* Handler for swapping page to swap disk. */
void swap_page(void *upage, struct spt_entry *entry)
{
  if (upage == 0x80e1000 || upage == 0x80e0000) {
    hex_dump (upage, upage, 8, false);
    printf("Dirty? %d\n", pagedir_is_dirty (thread_current ()->pagedir, upage));
  }
  printf("Swapping out page at %p, w? %d\n", upage, entry->writable);
  entry->swap_slot = swap_out(upage);
  if (entry->swap_slot == -1) {
    //Swap failed as swap disk is full
    exit_handler (ERROR);
  }
  entry->swapped = true;
  //printf("Swapping out page at %p, w? %d\n", upage, entry->writable);
  pagedir_clear_page(thread_current ()->pagedir, upage);
}

/* Function for eviction a filesys page. */
void evict_filesys(void *upage, struct spt_entry *entry)
{
  if (entry->writable)
  {
    swap_page(upage, entry);
  }
  else
  {
    pagedir_clear_page(thread_current ()->pagedir, upage);
  }
}

/* Function for eviction a mmap page. */
void evict_mmap(void *upage, struct spt_entry *entry)
{
  mm_file_write(entry->file, entry->rbytes, upage, entry->ofs);
}

/* Function for eviction a stack page. */
void evict_stack(void *upage, struct spt_entry *entry)
{
  swap_page(upage, entry);
}

/**
 * returns the frame allocated to the user process frame
 * kernel panic if new page cannot be allocated for now
 * TODO: eviction and replace*
 */
void *
get_frame(enum palloc_flags flag, void *user_page, struct file *file)
{
  ft_access_lock();
  void *kernel_page = palloc_get_page(flag);

  if (kernel_page == NULL)
  {
    //printf("No free frames available for allocation!\n");
    /*TODO: evict a frame and replace with new page allocation*/
    struct ft_entry *cur_ft = list_entry(list_pop_front(&snd_chance), struct ft_entry, ele_elem);
    ASSERT(cur_ft);
    while (true)
    {
      if (!cur_ft->pinned)
      {
        //printf("This page is not pinned\n");
        //void *cur_upage = list_entry(list_front(&cur_ft->owners), struct owner, owner_elem)->upage;
        void *cur_upage = cur_ft->upage;
        struct spt_entry *cur_spt = spt_lookup(cur_upage);
        //printf("%p", cur_upage);
        if (pagedir_is_accessed(thread_current()->pagedir, cur_upage))
        {
          //printf("Accessed bit of this page is set\n");
          pagedir_set_accessed(thread_current()->pagedir, cur_upage, false);
        }
        else
        {
          //printf("Accessed bit of this page is not set\n");
          switch (cur_spt->location)
          {
          case FILE_SYS:
            //printf("Evicting filesys page.\n");
            evict_filesys(cur_upage, cur_spt);
            break;

          case MMAP:
            //printf("Evicting mmap page.\n");
            evict_mmap(cur_upage, cur_spt);
            break;

          case STACK:
            //printf("Evicting stack page.\n");
            evict_stack(cur_upage, cur_spt);
            break;

          default:
            //printf("Evicting unknown page.\n");
            PANIC("Page stored in unknown location");
            break;
          }
          break;
        }
      }
      list_push_back(&snd_chance, &cur_ft->ele_elem);
      cur_ft = list_entry (list_pop_front (&snd_chance), struct ft_entry, ele_elem);
    }
    palloc_free_page (cur_ft->kernel_page);
    kernel_page = palloc_get_page (PAL_USER);
    ASSERT (kernel_page);
    //printf("eviction success\n");
  }
  struct ft_entry *entry = (struct ft_entry *)malloc(sizeof(struct ft_entry));
  if (!entry)
  {
    printf("Cannot alloc frame table entry!\n");
    return NULL;
  }
  entry->kernel_page = kernel_page;
  entry->upage = user_page;
  entry->file = file;
  entry->pinned = false;
  /*
  list_init(&entry->owners);
  struct owner *owner = (struct owner *)malloc(sizeof(struct owner));
  if (!owner)
  {
    printf("Cannot alloc frame page owner!\n");
    return NULL;
  }
  owner->process = thread_current();
  owner->upage = user_page;
  list_push_back(&entry->owners, &owner->owner_elem);
  */
  list_push_back(&snd_chance, &entry->ele_elem);
  
  hash_insert(&ft, &entry->ft_elem);
  ft_access_unlock();
  //printf("Frame of vmaddr: %p allocated\n", user_page);
  return kernel_page;
}

/*hash find finds the hash element based on an entry's KPAGE address*/
struct ft_entry *
ft_search_entry(void *kpage)
{
  struct ft_entry dummy;
  dummy.kernel_page = kpage;
  struct hash_elem *e = hash_find(&ft, &dummy.ft_elem);
  if (!e)
  {
    return NULL;
  }
  return hash_entry(e, struct ft_entry, ft_elem);
}

/**returns the page entry with the provided file name and page.
 *if entry does not exist, return NULL*/
struct ft_entry *
ft_search_frame_with_page(void *upage)
{
  /* iterate through frame table to find a match */
  struct hash_iterator i;
  hash_first(&i, &ft);
  while (hash_next(&i))
  {
    struct ft_entry *f = hash_entry(hash_cur(&i), struct ft_entry, ft_elem);
    struct list_elem *e = list_front(&f->owners);
    while (e != list_end(&f->owners))
    {
      struct owner *owner = list_entry(e, struct owner, owner_elem);
      if (owner->upage == upage)
      {
        return f;
      }
    }
  }
  return NULL;
}

/*remove and free frame for KPAGE*/
void free_frame(void *kpage)
{
  struct ft_entry *entry = ft_search_entry(kpage);
  hash_delete(&ft, &entry->ft_elem);
  palloc_free_page(entry->kernel_page);
  free(entry);
}

void ft_add_page_entry(struct ft_entry *entry)
{
  hash_insert(&ft, &entry->ft_elem);
}

static bool
ft_entry_comp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  void *a_address = hash_entry(a, struct ft_entry, ft_elem)->kernel_page;
  void *b_address = hash_entry(b, struct ft_entry, ft_elem)->kernel_page;
  return a_address < b_address;
}

/* Hash function: entry hashed by the upage address */
static unsigned int
ft_entry_hash(const struct hash_elem *a, void *aux UNUSED)
{
  const struct ft_entry *e = hash_entry(a, struct ft_entry, ft_elem);
  return hash_bytes(&e->kernel_page, sizeof(e->kernel_page));
}