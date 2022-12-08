#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>
#include "threads/thread.h"
#include "filesys/off_t.h"

#define ERROR -1
typedef int pid_t;
typedef int mapid_t;

void filesys_lock (void);
void filesys_unlock (void);
void syscall_init (void);
void exit_handler (int);

void mm_destroy (struct file_record *);
void mm_file_write(struct file *file, int size, void *upage, off_t ofs);

#endif /* userprog/syscall.h */
