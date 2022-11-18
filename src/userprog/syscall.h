#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>

#define PTSIZE 4

typedef int pid_t;

void filesys_lock (void);
void filesys_unlock (void);
void syscall_init (void);
void exit_handler (int);

#endif /* userprog/syscall.h */
