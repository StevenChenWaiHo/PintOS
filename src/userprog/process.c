#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads/malloc.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "vm/frame.h"
#include "vm/share.h"
#include "vm/spt.h"

/* Extra argument counts used in argument passing, containing null pointer,
   pointer to argv, argc, return adr. */
#define EXTRA_ARGS_NO 4   

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void check_pointer (int *start_ptr, int *esp);
static int *push_arguments (int *start_ptr, int *esp, int argc, int *argv);
static void *get_file_from_info (struct start_process_param *param_struct);
static struct child_thread_coord 
  *get_coord_from_info (struct start_process_param *param_struct);

/* Helper function for freeing child coordinators. */
static void free_child_coord (struct child_thread_coord *coord){
  list_remove (&coord->child_elem);
  free (coord);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute () returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{  
  enum intr_level old_level = intr_disable ();

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load (). */
  char *fn_copy;
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create struct for linkage between parent and child. */
  struct child_thread_coord 
    *child = malloc (sizeof (struct child_thread_coord));
  if (!child) {
    palloc_free_page (fn_copy); 
    printf ("Cannot allocate child_thread_coord\n");
    return TID_ERROR;
  }

  /* Initialize child_thread_coord if it is allocated successfully. */
  child->parent_is_terminated = false;
  child->waited = false;
  sema_init (&child->sema, 0);
  list_push_front (&thread_current ()->children, &child->child_elem);

  /* Define var information to pass to start_process.*/
  struct start_process_param 
    *param = malloc (sizeof (struct start_process_param));
  if (!param) {
    palloc_free_page (fn_copy); 
    printf ("Cannot allocate start_process_param\n");
    free_child_coord (child);
    return TID_ERROR;
  }
  
  /* Initialize start_process_param if it is allocated successfully. */
  param->filename = fn_copy;
  param->child_thread_coord = child;
  intr_set_level (old_level);

  /* Start child process. */
  tid_t tid = TID_ERROR;
  tid = thread_create (file_name, PRI_DEFAULT, start_process, param);
  if (tid == TID_ERROR) {
    free (param);
    free_child_coord (child);
    return TID_ERROR;
  }
  
  /* Blocks parent thread until success/failure of child loading executable
     is confirmed. start_process () will call set tid, then call sema_up to unblock 
     parent thread. */
  sema_down (&child->sema);
  old_level = intr_disable ();

  /* Free child_thread_coord and remove it from parent's children list if child
     is not loaded successfully. */
  if (child->tid == TID_ERROR) {
    free_child_coord (child);
    return TID_ERROR;
  }
  intr_set_level (old_level);
  return tid;  
}

static void *
get_file_from_info (struct start_process_param *param_struct){
  return param_struct->filename;
}

static struct child_thread_coord * 
get_coord_from_info (struct start_process_param *param_struct){
  return param_struct->child_thread_coord;
}

/* A thread function that loads a user process and starts it running. */
static void
start_process (void *param_struct) 
{
  enum intr_level old_level = intr_disable ();
  /* Extract function parameter from param_struct and free it after use. */
  struct start_process_param *param = param_struct;
  void *file_name = get_file_from_info (param);
  struct child_thread_coord *cur_coord = get_coord_from_info (param);
  thread_current ()->child_thread_coord = cur_coord;
  free (param);

  /* Create a new file_name copy for future uses and set thread's name. */
  char *sp;
  char *fn_copy = malloc (strlen (file_name) + 1);
  strlcpy (fn_copy, file_name, strlen (file_name) + 1);
  file_name = strtok_r (file_name, " ", &sp);
  strlcpy (thread_current ()->name, file_name, strlen (file_name) + 1);
  
  /* Initialize interrupt frame and load executable. */
  struct intr_frame if_;
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  intr_set_level (old_level);

  /* Load the executable and free the page after use. */
  bool success;
  success = load (file_name, &if_.eip, &if_.esp);  
  palloc_free_page (file_name);

  if (!success) 
  {
    /* Child fails to load, set exit status, child_is_terminated to true
       and sema_up to let parent to free the coord resources. */
    cur_coord->tid = TID_ERROR;
    cur_coord->exit_status = ERROR;
    cur_coord->child_is_terminated = true;
    sema_up (&cur_coord->sema);
    thread_exit ();
    NOT_REACHED ();
  }
  else
  {    
    /* Tokenise file_name and arguments. 
       Pointers to argv elements will be stored in a temporary page, 
       which will be freed right after pushing all arguments.
       When there are still more to tokenise, arguments will be
       memcpy'd to esp and added to argv for later stack pushes.
       Stack overflow checks are also done every push.*/
    int argc = 0;
    int *argv = palloc_get_page(PAL_USER);
    void *start_ptr = if_.esp;
    char *token = strtok_r (fn_copy, " ", &sp);
    while (token != NULL)
    {
      check_pointer (start_ptr, if_.esp -= (strlen (token)+1));
      memcpy (if_.esp, token, strlen (token)+1);
      argv[argc++] = (int) if_.esp;
      token = strtok_r (NULL, " ", &sp);
    }
    
    /* Push the rest of the stack. */
    if_.esp = (void *) push_arguments ((int *)start_ptr, (int *)if_.esp, argc, argv);
    palloc_free_page(argv);

    /* Set current coordinator's tid,
       then lift the semaphore to release parent thread. */
    cur_coord->tid = thread_current ()->tid;
    sema_up (&cur_coord->sema);
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Helper function to check for stack overflow. */
static void check_pointer (int *start_ptr, int *esp)
{
  if ((void *)start_ptr - (void *)esp >= PGSIZE)
  {
    exit_handler(ERROR);
  }
}

/* Helper function for push_arguments.
   Helps decrement esp and push whatever integer values passed
   onto the current stack position.*/
static int *push_stack (int *esp_adr, int arg) {
  esp_adr--;
  *esp_adr = arg;
  return esp_adr;
}

/* Basic stack pushing. */
static int *push_arguments (int *start_ptr, int *esp, int argc, int argv[])
{
    /* Word-alignment. */
    esp = (int *) ( (intptr_t) esp & 0xfffffffc);

    /* Check for stack overflow.
       With the total arguments that will be pushed onto stack known,
       only one check to the bottom of the stack is necessary.*/
    check_pointer(start_ptr, esp - sizeof(int *) * (argc + EXTRA_ARGS_NO));
    
    /* Push null pointer. */
    esp = push_stack (esp, 0);

    /* Push token addresses onto stack. */
    for (int i = argc - 1; i >= 0; i--)
    {
      esp = push_stack (esp, (int) argv[i]);
    }

    /* Push argv and argc. */
    int argv_pt = (int) esp;
    esp = push_stack (esp, argv_pt);
    esp = push_stack (esp, argc);

    /* Push fake return address = 0. */
    esp = push_stack (esp, 0);

    return esp;
}


/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait () has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid) 
{
  enum intr_level old_level = intr_disable ();

  /* Verify child, chid thread must be direct childeren (threads waited on will 
    be removed from list). */
  struct child_thread_coord *child_coord = NULL;
  struct list *children = &thread_current ()->children;
  if (!list_empty (children)){
    struct list_elem *child = list_front (children);
    while (child != list_end (children)) {
      struct child_thread_coord 
        *coord = list_entry (child, struct child_thread_coord, child_elem);
      if (coord->tid == child_tid)
      {
        child_coord = coord;
        if (child_coord->waited){
          return ERROR;
        }
        else{
          child_coord->waited = true;
        }
        break;
      }
      child = list_next (child);
    }
  }

  // Can't find children's tid in the children list.
  if (child_coord == NULL) {
    return ERROR;
  }

  intr_set_level (old_level);
  /* Situation 1: Child is not terminated
          The sema in child_thread_coord will block parent thread until it
          terminate and called sema_up (). 
    Situation 2: Child is terminated
          sema_up () is called when the child thread is terminated, thus parent 
          thread will not be blocked and acquire child's exit_status. */
  sema_down (&child_coord->sema);

  old_level = intr_disable ();

  /* Parent thread is unblocked, get exit_status, free its child's thread_coord 
  and remove the thread_coord from parent's children_list. */
  int ret = child_coord->exit_status;
  free_child_coord (child_coord);
  intr_set_level (old_level);

  return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  enum intr_level old_level = intr_disable ();

  /* Set the exit_code its child_thead_coord. */
  struct thread *cur = thread_current ();
  struct child_thread_coord *cur_coord = cur->child_thread_coord;
  cur_coord->exit_status = cur->exit_code;

  /* Free all the child coord which child has have terminated. */
  struct list *children_list = &thread_current ()->children;
  if (!list_empty (children_list)){
    struct list_elem *e = list_front (children_list);
    while (e != list_end (children_list)) {
      struct child_thread_coord *child_coord = list_entry (e, struct child_thread_coord, child_elem);
      child_coord->parent_is_terminated = true;
      struct list_elem *e_next = list_next (e);
      if (child_coord->child_is_terminated)
      {
        free_child_coord (child_coord);
      }
      e = e_next;
    }
  }
  intr_set_level (old_level);
  /* Closing all files that are still open in this process. 
     Corresponding file descriptor pairs are also freed here. */
  filesys_lock ();
  struct list *fd_ref_list = &thread_current ()->fd_ref;
  if (!list_empty (fd_ref_list)) {
    struct list_elem *e = list_front (fd_ref_list);
    while (e != list_end (fd_ref_list)) {
      struct file_record *open_file = list_entry (e, struct file_record, f_elem);
      file_close (open_file->file_ref);
      e = list_next (e);
      free (open_file);
    }
  }

  /* Closes the executable file of the current process, 
     raising the deny_write limit on the file system.*/
  file_close (cur->process_file);
  filesys_unlock ();
  /* Freeing MMAP elements by calling helper function for munmap. */
  struct list *mm_ref_list = &thread_current ()->mm_ref;
  if (!list_empty (mm_ref_list)) {
    struct list_elem *e = list_front (mm_ref_list);
    while (e != list_end (mm_ref_list)) {
      struct file_record *mm_pair = list_entry (e, struct file_record, f_elem);
      e = list_next (e);
      mm_destroy (mm_pair);
    }
  }
  
  /* Freeing SPT elements, removing entries in the swap disk. */
  spt_destroy ();

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  uint32_t *pd;
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  cur_coord->child_is_terminated = true;
  
  /* Free struct child_thread_coord if current thread is an orphan. */
  if (cur_coord->parent_is_terminated) {
      free_child_coord (cur_coord);
      return;
  }

  /* Should consult supplemental page table for any extra stuff to free here.*/


  sema_up (&cur->child_thread_coord->sema);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf (). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;

  process_activate ();

  /* Open executable file. */
  filesys_lock ();
  file = filesys_open (file_name);
  thread_current ()->process_file = file;
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  file_deny_write (file);
 
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;


 done:
  /* We arrive here whether the load is successful or not. */
  filesys_unlock ();
  return success;
}

/* load () helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ( (phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ( (void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ( (void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy (), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ( (read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  return
    lazy_load (file, ofs, upage, read_bytes, zero_bytes, writable, FILE_SYS);
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  uint8_t *upage = ((uint8_t *)PHYS_BASE) - PGSIZE;
  struct file *file = NULL;
  bool success = false;

  kpage = get_frame (PAL_USER | PAL_ZERO, upage, file);
  if (kpage != NULL) 
    {
      success = install_page (upage, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        free_frame (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page ().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
