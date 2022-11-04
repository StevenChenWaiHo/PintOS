#ifndef USERPROG
#define USERPROG

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>

#define PTSIZE 4

typedef int pid_t;

void syscall_init (void);

/* System call function prototypes. */
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void (*sys_call[13])() = {
    halt, exit, exec, wait,
    create, remove, open, filesize,
    read, write, seek, tell, close
};

#endif
#endif /* userprog/syscall.h */
