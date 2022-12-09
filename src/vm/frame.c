#include <hash.h>
#include <threads/malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"

struct hash ft;
struct lock ft_lock;

static bool ft_entry_comp(const struct hash_elem *, const struct hash_elem *, void * UNUSED);
static unsigned int ft_entry_hash(const struct hash_elem *, void * UNUSED);

void
ft_init(void)
{
    hash_init(&ft, ft_entry_hash, ft_entry_comp, NULL);
    lock_init(&ft_lock);
}

struct hash *
get_ft(void)
{
    return &ft;
}

void
ft_access_unlock(void)
{
    lock_release(&ft_lock);
}

void
ft_access_lock(void)
{
    lock_acquire(&ft_lock);
}

/**
 * returns the frame allocated to the user process frame
 * kernel panic if new page cannot be allocated for now
 * TODO: eviction and replace* 
*/
void *
get_frame(enum palloc_flags flag, void *upage, struct file *file)
{
    void *kernel_page = palloc_get_page(flag);

    if (kernel_page == NULL)
    {
        /*TODO: evict a frame and replace with new page allocation*/
        PANIC("No free frames available for allocation!\n");
        return NULL;
    }
    struct ft_entry *entry = (struct ft_entry *) malloc(sizeof(struct ft_entry));
    if (!entry)
    {
        printf("Cannot alloc frame table entry!\n");
        return NULL;
    }
    entry->kernel_page = kernel_page;
    entry->user_page = upage;
    entry->file = file;
    list_init(&entry->owners);
    struct owner *owner = (struct owner *) malloc(sizeof(struct owner));
    if (!owner)
    {
        printf("Cannot alloc frame page owner!\n");
        return NULL; 
    }
    owner->process = thread_current();    
    list_push_back(&entry->owners, &owner->owner_elem);
    hash_insert(&ft, &entry->ft_elem);
    return kernel_page;    
}

/*hash find finds the hash element based on an entry's KPAGE address*/
struct ft_entry *
ft_search_entry(void *upage)
{
  struct ft_entry dummy;
  dummy.user_page = upage;
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
    hash_first (&i, &ft);
    while (hash_next (&i))
    {
        struct ft_entry *f = hash_entry (hash_cur (&i), struct ft_entry, ft_elem);
        if (upage == f->user_page)
        {
            return f;                  
        }
    }
    return NULL;
}

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

/*remove and free frame for KPAGE*/
void
free_frame(void *kpage)
{
    struct ft_entry *entry = ft_search_entry(kpage);
    if (entry) {
        hash_delete(&ft, &entry->ft_elem);
        
        while (!list_empty (&entry->owners)) {
            struct list_elem *e = list_pop_front(&entry->owners);
            struct owner *owner = list_entry(e, struct owner, owner_elem);
            free(owner);
        }
    }
    free(entry);
}

void
ft_add_page_entry(struct ft_entry * entry) {
    hash_insert(&ft, &entry->ft_elem);
}

static bool
ft_entry_comp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    void *a_address = hash_entry(a, struct ft_entry, ft_elem)->user_page;
    void *b_address = hash_entry(b, struct ft_entry, ft_elem)->user_page;
    return a_address < b_address;
}

/* Hash function: entry hashed by the upage address */
static unsigned int
ft_entry_hash(const struct hash_elem *a, void *aux UNUSED)
{
    const struct ft_entry *e = hash_entry(a, struct ft_entry, ft_elem);
    return hash_bytes(&e->user_page, sizeof(e->user_page));
}