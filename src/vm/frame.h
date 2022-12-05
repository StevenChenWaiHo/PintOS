#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "threads/palloc.h"

struct ft_entry
{
    void *kernel_page;              /*page allocated in kernel virtual memory*/
    void *user_page;                /*page allocated in user virtual memory*/
    struct file *file;              /*name of the file this frame is storing*/
    struct list owners;             /*processes that owns the frame*/
    struct list_elem ele_elem;      /*list elem for eviction round robin list*/
    struct hash_elem ft_elem;       /*hash elem for frame table*/
};

void ft_init(void);
struct hash *get_ft(void);
void *get_frame(enum palloc_flags, void *, struct file*);
struct ft_entry * ft_search_entry(void *);
void free_frame(void *);
void ft_add_page_entry(struct ft_entry *); 

#endif /* vm/frame.h */