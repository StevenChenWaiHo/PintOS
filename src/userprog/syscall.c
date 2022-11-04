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

static void syscall_handler (struct intr_frame *);

int return_value;

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
  if (!is_user_vaddr(uaddr)
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
syscall_handler (struct intr_frame *f) {
  valid_pointer(f->esp);

  int args[3] = {0}; //?
  int arg_count = 1;
  void *p = f->esp;
  int sys_call_num = &p;

  if (sys_call_num == SYS_HALT)
    sys_call[SYS_HALT] ();

  if (sys_call_num == SYS_CREATE || sys_call_num == SYS_SEEK)
    arg_count = 2;
  else if (sys_call_num == SYS_READ || sys_call_num == SYS_WRITE) 
    arg_count = 3;

  for (int i = 0; i < arg_count; i++) {
    valid_pointer(p++);
    args[i] = &p;
  }

  switch (arg_count) {
    case 1: {
      sys_call[sys_call_num] (args[0]);
      break;
    }
    case 2: {
      sys_call[sys_call_num] (args[0], args[1]);
      break;
    }
    case 3: {
      sys_call[sys_call_num] (args[0], args[1], args[2]); 
      break;
    }
    default: {
      exit_handler();
    }
  }

  if (return_val()) {
    f->eax = return_value;
  }

  printf ("Call complete.");
  thread_exit ();
}

void
halt () {
  shutdown_power_off ();
}

void
exit (int status) {
  //? calls write?
  if (status == 0) {
    printf ("Process terminated successfully with exit code 0.\n");
  } else {
    printf ("Process terminated with error code %d", status);
  }
  exit_handler ();
}

int
write (int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf (buffer, size);
    return size;
  }
}