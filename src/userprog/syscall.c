#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "lib/kernel/stdio.h"
#include "vm/spt.h"

/* Total system calls implemented in Task 2. */
#define SYS_CALL_NUM 15

/* Global file system lock.*/
struct lock file_l;

/* System call function prototypes. */
static void halt        (uint32_t *, uint32_t *) NO_RETURN;
static void exit        (uint32_t *, uint32_t *) NO_RETURN;
static void exec        (uint32_t *, uint32_t *);
static void wait        (uint32_t *, uint32_t *);
static void file_create (uint32_t *, uint32_t *);
static void file_remove (uint32_t *, uint32_t *);
static void open        (uint32_t *, uint32_t *);
static void filesize    (uint32_t *, uint32_t *);
static void read        (uint32_t *, uint32_t *);
static void write       (uint32_t *, uint32_t *);
static void seek        (uint32_t *, uint32_t *);
static void tell        (uint32_t *, uint32_t *);
static void close       (uint32_t *, uint32_t *);
static void mmap        (uint32_t *, uint32_t *);
static void munmap      (uint32_t *, uint32_t *);

void syscall_init (void);
static void syscall_handler (struct intr_frame *);

static struct file *fd_search (int);
static struct file_record *fd_search_struct (int);
static void fd_destroy (int);
static struct file_record *mm_search_struct (int);
static struct file_record *search_struct (int, struct list *);

static bool mmap_available (void *, int);

/* Function pointer array for system calls. */
static void (*sys_call[SYS_CALL_NUM]) (uint32_t *, uint32_t *) = {
  halt, exit, exec, wait,
  file_create, file_remove, open, filesize,
  read, write, seek, tell, close,
  mmap, munmap
};
/* Corresponding argument counts of the above functions. */
static int args_count[SYS_CALL_NUM] = {
  0, 1, 1, 1,
  2, 1, 1, 1,
  3, 3, 2, 1, 1,
  2, 1
};

/* Acquire global file system lock. */
void filesys_lock (void)
{
  lock_acquire(&file_l);
}

/* Release global file system lock. */
void filesys_unlock (void)
{
  lock_release(&file_l);
}

void filesys_try_unlock (void)
{
  if (lock_held_by_current_thread (&file_l)) {
    filesys_unlock ();
  }
}

/* Initialization of system calls (called in init.c),
   Global lock is initialized here. */
void
syscall_init (void) 
{
  lock_init (&file_l);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Main exit handler for all occasions of terminating an execution.
   Sets the current thread as well as its corresponding
   child coordinator's status, and print out the exit message. 
   Thread_exit is then called to handle memory freed and thread destruction. */
void
exit_handler (int status) {
  thread_current ()->exit_code = status;
  thread_current ()->child_thread_coord->exit_status = status;
  printf ("%s: exit(%d)\n", thread_name (), status);
  thread_exit ();
  NOT_REACHED ();
}

/* Function handling checks to user-provided pointers.
   Calls functions to clear allocated memory to the current process
   and kills the current thread. */
static void
valid_pointer (const void *uaddr) {
  if (!is_user_vaddr (uaddr)
    || !pagedir_get_page (thread_current ()->pagedir, uaddr)) {
    if (!spt_pf_handler (uaddr, true, false, true, NULL)){
      exit_handler (ERROR);
    }
  }
}

/* Helper function for the buffer version of pointer validation.
   Calls valid_pointer at certain (offseted) pointers in every page
   the buffer spans. */
static void
valid_buffer (const void *buffer, off_t size, bool check_writable) {
  for (int i = 0; i < (size + pg_ofs(buffer)) / PGSIZE + 1; i++) {
    valid_pointer (buffer);
    if (check_writable && !pagedir_is_writable
      (thread_current()->pagedir, buffer)) {
        //printf ("Addr failing: %x\n", buffer);
        exit_handler (ERROR);
    }
    buffer += PGSIZE;
  }
}

/* Main system call handler.
   Takes advantage of the syscall_num enum and function pointers,
   preloads argument array and does pointer validation on them
   before calling the corresponding system calls. */
static void
syscall_handler (struct intr_frame *f) {
  //printf("Current esp= %p", f->esp);
  valid_pointer (f->esp);
  uint32_t args[3] = {0};
  uint32_t *p = f->esp;
  uint32_t *return_p = & (f->eax);

  int arg_count = 1;
  int sys_call_num = *p;

  if (sys_call_num >= SYS_CALL_NUM) {
    exit_handler (-1);
  } 

  for (int i = 0; i < args_count[sys_call_num]; i++) {
    valid_pointer (++p);
    args[i] = *p;
  }

  sys_call[sys_call_num] (args, return_p);
}

/* System calls implementations.
   After preloading the argument array, the values are passed into the
   function through function pointers and extracted (renamed) within
   the system calls (for readability).
   EAX of the intr_frame is passed as pointer into these system calls to 
   maintain consistent typing (for the pointer array to work),
   with UNUSED marked in functions that have no return. */

/* Halts the current program by directing invoking shutdown signal.*/
void
halt (uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  shutdown_power_off ();
  NOT_REACHED ();
}

/* Exits the current execution with status code in args[0].
   This is used only when an explicit call to exit is present
   in the user program. */
void
exit (uint32_t *args, uint32_t *eax UNUSED) {
  exit_handler ((int) args[0]);
  NOT_REACHED ();
}

/* Executes the command line CMD_LINE by directly calling process_execute
   and generating a child thread to handle the process.*/
void
exec (uint32_t *args, uint32_t *eax UNUSED) {
  const char *cmd_line = (char *) args[0];
  valid_pointer (cmd_line);
  *eax = process_execute (cmd_line);
}

/* Waits for a present child process with PID by calling process_wait. */
void
wait (uint32_t *args, uint32_t *eax UNUSED) {
  pid_t pid = args[0];
  *eax = process_wait (pid);
}

/* Creates a new file named FILE with fixed SIZE.
   This will fail when given an empty file name.*/
void
file_create (uint32_t *args, uint32_t *eax) {
  const char *file = args[0];
  unsigned size = args[1];

  valid_pointer (file);
  if (file[0] == '\0') {
    exit_handler (ERROR);
  }
  filesys_lock ();
  *eax = (uint32_t) filesys_create (file, size);
  filesys_unlock ();
}

/* Remove a file with the given file name FILE.*/
void
file_remove (uint32_t *args, uint32_t *eax) {
  const char *file = args[0];

  valid_pointer (file);

  filesys_lock ();
  *eax = (uint32_t) filesys_remove (file);
  filesys_unlock ();
}

/* Open a file with the given file name.
   Will fail silently if no file with the file name is found,
   otherwise will create a file descriptor pair entry FD_PAIR
   and return FD as ID. */
void
open (uint32_t *args, uint32_t *eax) {
  const char *file = args[0];

  valid_pointer (file);

  filesys_lock ();
  struct file *fp = (uint32_t) filesys_open (file);
  filesys_unlock ();

  if (!fp) {
    *eax = ERROR;
  } else {
    struct file_record *fd_pair = malloc (sizeof (struct file_record));
    if (fd_pair == NULL)
    {
      printf ("Cannot allocate fd_pair\n");
      return;
    }
    fd_pair->id = thread_current ()->curr_fd++;
    fd_pair->file_ref = fp;
    list_push_front (&thread_current ()->fd_ref, &fd_pair->f_elem);
    *eax = fd_pair->id;
  }

}

/* Return the file size with the given file descriptor ID.
   If the program attempts to check for STDIN and STDOUT,
   ERROR = -1 is returned.*/
void
filesize (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  if (fd >= 2) {
    struct file *fp = fd_search (fd);
    if (fp) {
      filesys_lock ();  
      *eax = (uint32_t) file_length (fp); 
      filesys_unlock (); 
      return;
    }
  }
  *eax = ERROR;
}

/* Read the file with a certain buffer size.
   First, it searches for the pointer to the file FP,
   with the file descriptor ID.
   After validating buffer and checking that it is not reading in STDOUT,
   it will either read from STDIN or from the file. */
void
read (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  void *buffer = args[1];
  off_t size = args[2];
  /*
  printf("%x", buffer);
  struct spt_entry *entry = spt_lookup (buffer);
  
  if (!entry) 
    printf("a\n\n\n\n\n\n");
  else
    printf("location: %d, writable: %d\n", entry->location, entry->writable);
  */

  valid_buffer (buffer, size, true);

  if (fd == STDOUT_FILENO) {
    exit_handler (ERROR);
  } else if (fd == STDIN_FILENO) {
    uint8_t *buf8 = (uint8_t *) buffer;
    for (int i = 0; i < size; i++) {
      buf8[i] = input_getc ();
    }
    *eax = size;
  } else {
    struct file *fp = fd_search (fd);
    filesys_lock ();
    *eax = file_read (fp, buffer, size);
    filesys_unlock ();
  }
}

/* Write to the file with a certain buffer size.
   First, it searches for the pointer to the file FP,
   with the file descriptor ID.
   After validating BUFFER and checking that it is not writing in STDIN,
   it will either write to STDOUT with PUTBUF or to the file. */
void
write (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  const void *buffer = (void *) args[1];
  off_t size = args[2];
  
  valid_buffer (buffer, size, false);

  if (fd == STDIN_FILENO) {
    exit_handler (ERROR);
  } else if (fd == STDOUT_FILENO) {
    putbuf (buffer, size);
    *eax = size;
  } else {
    struct file *fp = fd_search (fd);
    filesys_lock ();
    *eax = file_write (fp, buffer, size);
    filesys_unlock ();
  }
}

/* Sets the current inode position in FP (with file descriptor FD) to POSITION.
   Seek past file size is handled in file system code so no checks are needed.*/
void
seek (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
  off_t position = args[1];

  struct file *fp = fd_search (fd);
  filesys_lock ();
  file_seek (fp, position);
  filesys_unlock ();
}

/* Return the current inode position in FP (with file descriptor FD). */
void
tell (uint32_t *args, uint32_t *eax) {
  int fd = args[0];

  struct file *fp = fd_search (fd);

  filesys_lock ();
  *eax = file_tell (fp);
  filesys_unlock ();
}

/* Close the file corresponding to file descriptor FD.
   File descriptor pair is also destroyed(freed) in the process.*/
void
close (uint32_t *args, uint32_t *eax UNUSED) {
  int fd = args[0];
  fd_destroy (fd);
}

/* Memory Mapping functions. */

/* Helper function that iterate through every consecutive page of ADDR
  to check for availability for mapping into memory.*/
static bool mmap_available (void *addr, int read_bytes) {
  while (read_bytes > 0) {
    if (spt_lookup (addr)) {
      return false;
    }
    addr += PGSIZE;
    read_bytes -= PGSIZE;
  }
  return true;
}

/* Maps a file of descriptor FD to virtual address ADDR. */
void
mmap (uint32_t *args, uint32_t *eax) {
  int fd = args[0];
  void *addr = (void *) args[1];
  //printf("mmaping at %p\n", addr);
  /* Checking for fd, addr fails. */
  if (fd >= 2 && addr != 0 && pg_ofs (addr) == 0
    && (PHYS_BASE - (int) addr) > STACK_MAX) {
    struct file *fp = fd_search (fd);
    if (fp) {
      //Needs to renew thru reopen for unix convention of closing files
      filesys_lock ();
      fp = file_reopen (fp);
      int read_bytes = file_length (fp);
      filesys_unlock ();
      /* Checking for file size, overlapping pages fails.*/
      if (read_bytes > 0 && mmap_available (addr, read_bytes)) {
        int zero_bytes = (read_bytes % PGSIZE == 0) ? 
          0 : PGSIZE - (read_bytes % PGSIZE);

        //Do we assume writable is true here and leave blocking writes to
        //executable file for deny-writed calls to file_write?
        lazy_load (fp, 0, addr, read_bytes, zero_bytes, true, MMAP);

        /* Insert MMAP pair into MM_REF,
          allocating a new MAPID to the mapping. */
        struct file_record *mm_pair = malloc (sizeof (struct file_record));
        if (mm_pair == NULL)
        {
          printf ("Cannot allocate mm_pair\n");
          return;
        }
        mm_pair->id = thread_current ()->curr_mapid++;
        mm_pair->file_ref = fp;
        mm_pair->mapping_addr = addr;
        list_push_front (&thread_current ()->mm_ref, &mm_pair->f_elem);
        *eax = mm_pair->id;
        return;
      }
    }
  }
  *eax = ERROR;
}

void mm_file_write(struct file *file, int size, void *upage, off_t ofs, uint32_t *pd) 
{
  // ASSERT (pagedir_get_page (pd, upage));
  if (pagedir_is_dirty (pd, upage)) {
      if (size < PGSIZE) {
        file_write_at (file, upage, size, ofs);
      } else {
        file_write_at (file, upage, PGSIZE, ofs);        
      }
    } 
    pagedir_clear_page (pd, upage);
}

/* Helper function to destroy MMAP pair when closing a file. */
void
mm_destroy (struct file_record *e) {
  //Some munmap stuff here
  filesys_lock ();
  int size = file_length (e->file_ref);
  void *upage = e->mapping_addr;
  /* Iterating through all pages, checking dirty state and writing any dirty ones
    if this is the last page and is not full, trims the current upage content.*/
  while (size > 0) {
    void *kpage = pagedir_get_page (thread_current()->pagedir, upage);
    mm_file_write(e->file_ref, size, upage, upage - e->mapping_addr, thread_current ()->pagedir);
    spt_remove (upage);
    palloc_free_page (kpage);
    upage += PGSIZE;
    size -= PGSIZE;
  }
  file_close(e->file_ref);
  filesys_unlock();
  list_remove (&e->f_elem);
  free (e);
}

/* Unmaps the mapping of id MAPPING by calling helper function
  on the search result. */
void
munmap (uint32_t *args, uint32_t *eax) {
  mapid_t mapping = args[0];
  struct file_record *e = mm_search_struct (mapping);
  mm_destroy (e);
}

/* File descriptor storage list and search functions. */

/* Helper function to directly extract the file pointer in the pair. */
static struct file *fd_search (int fd) {
  return fd_search_struct (fd)->file_ref;
}

static struct file_record *fd_search_struct (int fd) {
  return search_struct (fd, &thread_current ()->fd_ref);
}

/* Helper function to destroy file descriptor pair when closing a file. */
static void fd_destroy (int fd) {
  struct file_record *e = fd_search_struct (fd);

  filesys_lock ();
  file_close (e->file_ref);
  filesys_unlock ();

  list_remove (&e->f_elem);
  free (e);
}

static struct file_record *mm_search_struct (mapid_t id) {
  return search_struct (id, &thread_current ()->mm_ref);
}

/* Search function that iterates through the FD_REF list
   and match their file descriptor ID with the passed argument FD.
   If not found, a stricter design is implemented here
   and the process will exit with ERROR code. */
static struct file_record *search_struct (int id, struct list *lp) {
  struct list_elem *e;

  for (e = list_begin (lp); e != list_end (lp);
       e = list_next (e)) {
    struct file_record *curr = 
      list_entry (e, struct file_record, f_elem);
    if (curr->id == id)
      return curr;
  }
  exit_handler (ERROR);
  NOT_REACHED ();
}
