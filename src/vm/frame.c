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
static uint32_t ft_entry_hash(const struct hash_elem *, void * UNUSED);

void
ft_init()
{
    hash_init(&ft, ft_entry_hash, ft_entry_comp, NULL);
    lock_init(&ft_lock);
}

/**
 * returns the frame allocated to the user process frame
 * kernel panic if new page cannot be allocated for now
 * TODO: eviction and replace* 
*/
void *
get_frame(void *user_page)
{
    lock_acquire(&ft_lock);
    void *kernel_page = palloc_get_page(PAL_USER);

    if (kernel_page == NULL)
    {
        /*TODO: evict a frame and replace with new page allocation*/
        lock_release(&ft_lock);
        PANIC("No free frames available for allocation!\n");
        return NULL;
    }
    struct ft_entry *entry = (struct ft_entry *) malloc(sizeof(struct ft_entry));
    if (!entry)
    {
        lock_release(&ft_lock);
        printf("Cannot alloc frame table entry\n");
        return NULL;
    }
    entry->kernel_page = kernel_page;
    entry->user_page = user_page;
    list_init(&entry->owners);
    list_push_back(&entry->owners, &thread_current()->frame_elem);
    hash_insert(&ft, &entry->ft_elem);
    lock_release(&ft_lock);
    return entry;    
}

void
free_frame(struct ft_entry *entry)
{
    hash_delete(&ft, &entry->ft_elem);
    palloc_free_page(entry->kernel_page);
    free(entry);

}

void
ft_add_page_entry(struct ft_entry * entry) {
    hash_insert(&ft, &entry->ft_elem);
}

static bool
ft_entry_comp(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
    void *a_address = hash_entry(a, struct ft_entry, ft_elem)->kernel_page;
    void *b_address = hash_entry(b, struct ft_entry, ft_elem)->kernel_page;
    return a_address < b_address;
}

static uint32_t
ft_entry_hash(const struct hash_elem *a, void *aux)
{
    return hash_entry(a, struct ft_entry, ft_elem)->kernel_page;
}