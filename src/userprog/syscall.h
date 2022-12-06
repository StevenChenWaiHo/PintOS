#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>

#define ERROR -1
typedef int pid_t;
typedef int mapid_t;

void filesys_lock (void);
void filesys_unlock (void);
void syscall_init (void);
void exit_handler (int);

#endif /* userprog/syscall.h */
