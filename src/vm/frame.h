#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "threads/palloc.h"

struct ft_entry
{
    void *kpage;                    /* Page allocated in kernel virtual memory. */
    void *upage;                    /* Page allocated in user virtual memory. */
    struct file *file;              /* Name of the file this frame is storing. */
    struct list owners;             /* Processes that owns the frame. */
    struct thread *t;               /* Thread of this frame. */
    bool pinned;                    /* Boolean for pinned frame. */
    struct list_elem ele_elem;      /* List elem for eviction round robin list. */
    struct hash_elem ft_elem;       /* Hash elem for frame table. */
};

struct owner
{
    struct thread *process;         /* Owner thread of the current frame. */
    struct list_elem owner_elem;    /* List elem for owners list. */
};

void ft_init(void);
struct hash *get_ft(void);
void ft_access_lock(void);
void ft_access_unlock(void);
void ft_add_page_entry(struct ft_entry *);
struct ft_entry * ft_search_entry(void *);
void free_frame(void *);
void ft_free (struct thread *);
void *get_frame(enum palloc_flags, void *, struct file*);

#endif /* vm/frame.h */