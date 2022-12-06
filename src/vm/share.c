#include <hash.h>
#include <list.h>
#include <threads/malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include "vm/share.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/synch.h"

struct hash st;
struct lock st_lock;

static bool st_entry_comp(const struct hash_elem *, const struct hash_elem *, void * UNUSED);
static unsigned int st_entry_hash(const struct hash_elem *, void * UNUSED);

void
st_init(void)
{
    hash_init(&st, st_entry_hash, st_entry_comp, NULL);
    lock_init(&st_lock);
}

struct hash *
get_st(void)
{
    return &st;
}

void st_access_lock(void)
{
    lock_acquire(&st_lock);
}

void st_access_unlock(void)
{
    lock_release(&st_lock);
}

void
st_free_share_entry(struct st_entry *entry)
{
    free(entry);
}

struct st_entry *
st_find_share_entry(struct file *file)
{
    struct st_entry dummy;
    dummy.file = file;
     struct hash_elem *e = hash_find(&st, &dummy.st_elem);
    if (!e)
    {
        return NULL;
    }
    return hash_entry(e, struct st_entry, st_elem);
}


/** returns the frame table entry associated with the UPAGE of FILE.
 * Returns NULL if no frame allocated at UPAGE
*/
struct ft_entry *
st_find_frame_for_upage (void *upage, struct file *file)
{
    struct st_entry *entry = st_find_share_entry (file);
    if (!entry)
    {
        return NULL;
    }
    struct ft_entry * fte = NULL;
    struct list_elem *e = list_front (&entry->upages);
    while (e != list_end (&entry->upages))
    {
        struct share_frame_info *info = list_entry(e, struct share_frame_info, page_elem);
        if (info->upage == upage) {
            fte = info->frame;
        }
    }
    return fte;  
}

/*Insert share entry for FILE and update owners with new owner UPAGE at FRAME fte.*/
bool
st_insert_share_entry(struct file *file, void *upage, struct ft_entry *fte)
{
    struct share_frame_info *info = (struct share_frame_info *)malloc(sizeof(struct share_frame_info));
    if (!info)
    {
        printf("Cannot alloc share_frame_info for st_entry!\n");
        return false; 
    }
    // printf("st_insert_share_entry:: can malloc share_frame_info for st_entry!\n");
    info->frame = fte;
    info->upage = upage;

    struct st_entry *e = st_find_share_entry (file);
    if (!e)
    {
        e = (struct st_entry *)malloc(sizeof(struct st_entry));
        if (!e)
        {
            printf("Cannot alloc share_frame_info for st_entry!\n");
            return false; 
        }
        e->file = file;
        list_init(&e->upages);
        
        hash_insert(&st, &e->st_elem);
        // printf("new share table entry created succesfully\n");
    }
    
    list_push_back(&e->upages, &info->page_elem);
    return true;
}

/*remove and free file entry for FILE. Returns true if FILE is removed */
bool
st_free_entry (struct file *file)
{
    struct st_entry *entry = st_find_share_entry(file);
    if (entry)
    {
        struct list_elem *e = list_front (&entry->upages);
        while (e != list_end (&entry->upages))
        {
            struct share_frame_info *info = list_entry(e, struct share_frame_info, page_elem);
            free(info);
        }
        hash_delete(&st, &entry->st_elem);
        free(entry);
        return true;
    }
    return false;
}

/* Share table hash function: entry hashed by the file pointer */
static unsigned int
st_entry_hash(const struct hash_elem *a, void *aux UNUSED)
{
    const struct st_entry *e = hash_entry (a, struct st_entry, st_elem);
    return hash_bytes(e->file, sizeof(e->file));
}

/* Share table less than function */
static bool
st_entry_comp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct file *file_a = hash_entry (a, struct st_entry, st_elem)->file;
    struct file *file_b = hash_entry (b, struct st_entry, st_elem)->file;

    return file_a < file_b;
}