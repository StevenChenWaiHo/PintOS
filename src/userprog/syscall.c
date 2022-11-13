#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"
#include "devices/shutdown.h"
#include "lib/kernel/stdio.h"

#define SYS_CALL_NUM 13

struct lock file_l;

/* System call function prototypes. */
void halt        (uint32_t *, uint32_t *) NO_RETURN;
void exit        (uint32_t *, uint32_t *) NO_RETURN;
void exec        (uint32_t *, uint32_t *);
void wait        (uint32_t *, uint32_t *);
void file_create (uint32_t *, uint32_t *);
void file_remove (uint32_t *, uint32_t *);
void open        (uint32_t *, uint32_t *);
void filesize    (uint32_t *, uint32_t *);
void read        (uint32_t *, uint32_t *);
void write       (uint32_t *, uint32_t *);
void seek        (uint32_t *, uint32_t *);
void tell        (uint32_t *, uint32_t *);
void close       (uint32_t *, uint32_t *);

void syscall_init (void);
static void exit_handler (int);

/* Function pointer array for system calls. */
void (*sys_call[SYS_CALL_NUM])(uint32_t *, uint32_t *) = {
    halt, exit, exec, wait,
    file_create, file_remove, open, filesize,
    read, write, seek, tell, close
};

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init (&file_l);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
exit_handler (int status) {
  thread_current ()->exit_code = status;
  printf ("%s: exit(%d)\n", thread_name(), thread_current ()->exit_code);
  thread_exit ();
  NOT_REACHED ();
}

/*  Function handling checks to user-provided pointers.
 *  Calls functions to clear allocated memory to the current process
 *  and kills the current thread. */
static void
valid_pointer (const void *uaddr) {
  if (!is_user_vaddr (uaddr)
    || !pagedir_get_page(thread_current ()->pagedir, uaddr)) {
    printf("Invalid memory access.\n");
    exit_handler (-1);
  }
}

static void
syscall_handler (struct intr_frame *f) {
  
  valid_pointer(f->esp);
  uint32_t args[3] = {0};
  uint32_t *p = f->esp;
  uint32_t *return_p = &(f->eax);

  //hex_dump(p - 24, p - 24, 96, true);

  int arg_count = 1;
  int sys_call_num = *p;

  if (sys_call_num == SYS_HALT)
    sys_call[SYS_HALT] (args, return_p);

  if (sys_call_num == SYS_CREATE || sys_call_num == SYS_SEEK)
    arg_count = 2;
  else if (sys_call_num == SYS_READ || sys_call_num == SYS_WRITE) 
    arg_count = 3;

  for (int i = 0; i < arg_count; i++) {
    valid_pointer(++p);
    args[i] = *p;
  }

  //printf("Executing sys_call %d\n", sys_call_num);
  sys_call[sys_call_num] (args, return_p);

  //printf ("Call type of %d complete.\n", sys_call_num);
}

void
halt (uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  shutdown_power_off ();
  NOT_REACHED ();
}

void
exit (uint32_t *args, uint32_t *eax UNUSED) {
  exit_handler ((int) args[0]);
  NOT_REACHED ();
}

void
exec (uint32_t *args, uint32_t *eax UNUSED) {
  const char *cmd_line = (char *) args[0];
}

void
wait (uint32_t *args, uint32_t *eax UNUSED) {
  pid_t pid = args[0];
}

void
file_create (uint32_t *args, uint32_t *eax) {
  //printf("Creating file...");
  const char *file = args[0];
  unsigned size = args[1];

  valid_pointer(file);

  lock_acquire (&file_l);
  *eax = (uint32_t) filesys_create (file, size);
  lock_release (&file_l);
}

void
file_remove (uint32_t *args, uint32_t *eax UNUSED) {
  const char *file = args[0];

  valid_pointer(file);

  lock_acquire (&file_l);
  *eax = (uint32_t) filesys_remove(file);
  lock_release (&file_l);
}

void
open (uint32_t *args, uint32_t *eax UNUSED) {
  const char *file = args[0];
}

void
filesize (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
}


void
read (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
  void *buffer = args[1];
  unsigned size = args[2];
}

void
write (uint32_t *args, uint32_t *eax) {
  //printf("Writing...\n");
  int fd = args[0];
  const void *buffer = (void *) args[1];
  unsigned size = args[2];
  //valid_pointer(&buffer);
  if (fd == 1) {
    putbuf (buffer, size);
  }
  *eax = size;
}

void
seek (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
  unsigned position = args[1];
}


void
tell (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
}


void
close (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
}