#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>

struct ft_entry
{
    void *kernel_page;              /*page allocated in kernel virtual memory*/
    void *user_page;                /*page allocated in user virtual memory*/
    struct list *owners;            /*processes that owns the frame*/
    struct list_elem ele_elem;      /*list elem for eviction round robin list*/
    struct hash_elem ft_elem;       /*hash elem for frame table*/
};

#endif /* vm/frame.h */