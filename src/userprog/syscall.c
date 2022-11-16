#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "lib/kernel/stdio.h"

#define SYS_CALL_NUM 13

#define HANDLER_GET_ARG();
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
static struct file *fd_search (int);
static struct fd_elem_struct *fd_search_struct (int);
static void fd_destroy (int);
static void syscall_handler (struct intr_frame *);

/* Function pointer array for system calls. */
void (*sys_call[SYS_CALL_NUM])(uint32_t *, uint32_t *) = {
    halt, exit, exec, wait,
    file_create, file_remove, open, filesize,
    read, write, seek, tell, close
};

void filesys_lock(void)
{
  lock_acquire(&file_l);
}

void filesys_unlock(void)
{
  lock_release(&file_l);
}

void
syscall_init (void) 
{
  lock_init (&file_l);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
exit_handler (int status) {
  thread_current ()->exit_code = status;
  thread_current ()->child_thread_coord->exit_status = status;
  printf("Tid:%d, name: %s: exit(%d)\n", thread_current()->tid, thread_name(), thread_current()->exit_code);
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
    exit_handler (-1);
  }
}

static void
syscall_handler (struct intr_frame *f) {
  valid_pointer(f->esp);
  uint32_t args[3] = {0};
  uint32_t *p = f->esp;
  uint32_t *return_p = &(f->eax);

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
  valid_pointer(cmd_line);
  *eax = process_execute(cmd_line);
}

void
wait (uint32_t *args, uint32_t *eax UNUSED) {
  pid_t pid = args[0];
  *eax = process_wait(pid);
  if (*eax == -1) {
    printf("Thread returning -1 is tid:%d\n", thread_current()->tid);
  }
}

void
file_create (uint32_t *args, uint32_t *eax) {
  const char *file = args[0];
  unsigned size = args[1];

  valid_pointer (file);
  if (file[0] == '\0') {
    exit_handler (-1);
  }
  filesys_lock ();
  *eax = (uint32_t) filesys_create (file, size);
  filesys_unlock ();
}

void
file_remove (uint32_t *args, uint32_t *eax) {
  const char *file = args[0];

  valid_pointer (file);

  filesys_lock ();
  *eax = (uint32_t) filesys_remove(file);
  filesys_unlock ();
}

void
open (uint32_t *args, uint32_t *eax) {
  const char *file = args[0];

  valid_pointer (file);

  filesys_lock ();
  struct file *fp = (uint32_t) filesys_open(file);
  filesys_unlock ();

  if (!fp) {
    *eax = -1;
  } else {
    struct fd_elem_struct *fd_pair = malloc (sizeof (struct fd_elem_struct));
    fd_pair->fd = thread_current ()->curr_fd++;
    fd_pair->file_ref = fp;
    list_push_front (&thread_current ()->fd_ref, &fd_pair->fd_elem);
    *eax = fd_pair->fd;
  }

}

void
filesize (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  if (fd >= 2) {
    struct file *fp = fd_search (fd);

    filesys_lock ();
    *eax = (uint32_t) file_length (fp);
    filesys_unlock ();
    return;
  }
  *eax = -1;
}


void
read (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  void *buffer = args[1];
  off_t size = args[2];

  struct file *fp = fd_search (fd);

  valid_pointer (buffer);
  valid_pointer (buffer + size);

  if (fd == 1) {
    exit_handler (-1);
  } else if (fd == 0) {
    uint8_t *buf8 = (uint8_t *) buffer;
    for (int i = 0; i < size; i++) {
      buf8[i] = input_getc ();
    }
    *eax = size;
  } else {
    filesys_lock();
    *eax = file_read (fp, buffer, size);
    filesys_unlock();
  }
}

void
write (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  const void *buffer = (void *) args[1];
  off_t size = args[2];
  
  valid_pointer (buffer);
  valid_pointer (buffer + size);

  if (fd == 1) {
    putbuf (buffer, size);
    *eax = size;
  } else {
    struct file *fp = fd_search (fd);

    filesys_lock();
    *eax = file_write (fp, buffer, size);
    filesys_unlock();
  }
}

void
seek (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
  off_t position = args[1];

  struct file *fp = fd_search (fd);
  filesys_lock();
  file_seek (fp, position);
  filesys_unlock();
}


void
tell (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];

  struct file *fp = fd_search (fd);

  filesys_lock();
  *eax = file_tell (fd);
  filesys_unlock();
}


void
close (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
  fd_destroy (fd);
}

static struct file *fd_search (int fd) {
  return fd_search_struct (fd)->file_ref;
}

static struct fd_elem_struct *fd_search_struct (int fd) {
  struct list_elem *e;
  struct list *fd_ref_list = &thread_current()->fd_ref;

  for (e = list_begin (fd_ref_list); e != list_end (fd_ref_list);
       e = list_next (e)) {
    struct fd_elem_struct *curr = 
      list_entry (e, struct fd_elem_struct, fd_elem);
    if (curr->fd == fd)
      return curr;
  }
  exit_handler (-1);
  NOT_REACHED ();
}

static void fd_destroy (int fd) {
  struct fd_elem_struct *e = fd_search_struct (fd);

  filesys_lock();
  file_close (e->file_ref);
  filesys_unlock();

  list_remove (&e->fd_elem);
  free (e);
}