#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  //TODO: Implement stack initialization
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*  Function handling checks to user-provided pointers.
    Calls functions to clear allocated memory to the current process
    and kills the current thread. */
static void
valid_pointer (const void *uaddr) {
  //? Check for 3 arg fields?
  if (!is_user_vaddr()
    || !pagedir_get_page(thread_current()->pagedir, uaddr)) {
    exit_handler ();
  }
}

static void
exit_handler () {
  //? Only these two functions?
  process_exit ();
  thread_exit ();
}

static void
syscall_handler (struct intr_frame *f) 
{
  valid_pointer(f->esp);
  int args[3] = {0}; //?
  void *p = f->esp;
  int sys_call_num = &p;
  switch (sys_call_num) {
    case SYS_HALT: 
    {
      sys_call[SYS_HALT] ();
    }
    case SYS_EXIT: case SYS_EXEC: case SYS_WAIT:
    case SYS_REMOVE: case SYS_OPEN: case SYS_FILESIZE:
    case SYS_TELL: case SYS_CLOSE:
    {
      valid_pointer(p++);
      args[0] = &p;
      sys_call[sys_call_num] (args[0]);
    }
    case SYS_CREATE: case SYS_SEEK:
    {
      valid_pointer(p++);
      args[1] = &p;
      sys_call[sys_call_num] (args[0], args[1]);
    }
    case SYS_READ: case SYS_WRITE:
    {
      valid_pointer(p++);
      args[2] = &p;
      sys_call[sys_call_num] (args[0], args[1], args[2]);
    }
    default:
    {
      exit_handler ();
    }
  }
  printf ("Call complete.");
  thread_exit ();
}

void halt() {
  exit_handler ();
}

void exit(int status) {
  if (status == 0) {
    printf ("Process terminated successfully with exit code 0.\n");
  } else {
    printf ("Process terminated with error code %d", status);
  }
  exit_handler ();
}