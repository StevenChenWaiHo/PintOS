#define USERPROG
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>

#define PTSIZE 4

typedef int pid_t;

void syscall_init (void);

#endif /* userprog/syscall.h */
