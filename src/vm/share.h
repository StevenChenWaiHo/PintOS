#ifndef ST_TABLE_H
#define ST_TABLE_H

#include <hash.h>
#include <list.h>

struct st_entry
{
    char *file_name;              /*file pointer*/
    struct list upages;           /*pages file is loaded into*/
    struct hash_elem st_elem;     /*hash elem for share entry in page table*/
};

struct share_frame_info
{
    struct ft_entry *frame;     /* frame associated with the upage*/
    void * upage;               /* upage of the page */
    struct list_elem page_elem; /* list elem for list upages in an st_entry */
};

void st_init(void);
void st_printf(void);
struct hash *get_st(void);
void st_access_lock(void);
void st_access_unlock(void);
void st_free_share_entry(struct st_entry*);
struct st_entry *st_find_share_entry(char *);
struct ft_entry *st_find_frame_for_upage (void *, char *);
bool st_insert_share_entry(char *, void *, struct ft_entry *);
bool st_free_entry (char *);

#endif /* vm/share.h */