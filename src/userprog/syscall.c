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
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*  Function handling checks to user-provided pointers.
    Calls functions to clear allocated memory to the current process
    and kills the current thread. */
void
valid_pointer (uint32_t *pd, const void *uaddr) {
  if (pagedir_get_page(pd, uaddr) == NULL || !is_user_vaddr(uaddr)) {
    process_exit();
    thread_exit();
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
