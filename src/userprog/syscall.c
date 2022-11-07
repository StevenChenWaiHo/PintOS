#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"
#include "devices/shutdown.h"
#include "lib/kernel/stdio.h"

#define SYS_CALL_NUM 13

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
static void exit_handler (void);

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
  //TODO: Implement stack initialization
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
exit_handler (void) {
  thread_exit ();
  NOT_REACHED ();
}

/*  Function handling checks to user-provided pointers.
 *  Calls functions to clear allocated memory to the current process
 *  and kills the current thread. */
static void
valid_pointer (const void *uaddr) {
  //? Check for 3 arg fields?
  if (!is_user_vaddr (uaddr)
    || !pagedir_get_page(thread_current ()->pagedir, uaddr)) {
    exit_handler ();
  }
}

static void
syscall_handler (struct intr_frame *f) {
  valid_pointer(f->esp);

  uint32_t args[3] = {0};
  uint32_t *p = f->esp;
  uint32_t *return_p = &f->eax;

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

  sys_call[sys_call_num] (args, return_p);

  printf ("Call complete.");
  thread_exit ();
}

void
halt (uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  shutdown_power_off ();
  NOT_REACHED ();
}

void
exit (uint32_t *args, uint32_t *eax UNUSED) {
  thread_current ()->exit_code = args[0];
  exit_handler ();
  NOT_REACHED ();
}

void
exec (uint32_t *args, uint32_t *eax UNUSED) {
  const char *cmd_line = (char *) args[0];
}

void
wait (uint32_t *args, uint32_t *eax UNUSED) {

}

void
file_create (uint32_t *args, uint32_t *eax UNUSED) {

}

void
file_remove (uint32_t *args, uint32_t *eax UNUSED) {

}

void
open (uint32_t *args, uint32_t *eax UNUSED) {

}

void
filesize (uint32_t *args, uint32_t *eax UNUSED) {

}


void
read (uint32_t *args, uint32_t *eax UNUSED) {

}

void
write (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  const void *buffer = (void *) args[1];
  unsigned size = args[2];
  if (fd == 1) {
    putbuf (buffer, size);
  }
  *eax = size;
}

void
seek (uint32_t *args, uint32_t *eax UNUSED) {

}


void
tell (uint32_t *args, uint32_t *eax UNUSED) {

}


void
close (uint32_t *args, uint32_t *eax UNUSED) {

}