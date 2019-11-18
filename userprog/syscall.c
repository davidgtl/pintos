#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool validate_pointer(void *p)
{
  return is_user_vaddr(p) && p != NULL && lookup_page(thread_current()->pagedir, p, false) != NULL;
}

bool validate_string(char *str, int size)
{
  for (char *c = str; c != NULL && c - str <= size; c++)
  {
    if (!validate_pointer(c))
    {
      return false;
    }
  }
  return true;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  if (f->esp > PHYS_BASE - 12)
  {
    thread_exit();
    return;
  }

  int syscall_no = ((int *)f->esp)[0];
  int ok;
  int number;
  int fd;
  char c;
  char *str;

  switch (syscall_no)
  {
  case SYS_EXEC:
    str = ((char **)f->esp)[1];
    if(!validate_string(str,PGSIZE))
    {
      f->eax = 1;
      break;
    }
    process_execute(str);
    break;
  case SYS_WAIT:
    number = ((int *)f->esp)[1];
    process_wait(str);
    break;
  case SYS_EXIT:
    number = ((int *)f->esp)[1];
    process_exit(number);
    break;
  case SYS_WRITE:
    fd = ((int *)f->esp)[1];
    if (fd == 0)
    {
      f->eax = 1;
      break;
    }
    else if (fd == 1)
    {
      str = ((char **)f->esp)[2];
      number = ((int *)f->esp)[3];
      if(!validate_string(str,number))
      {
        f->eax = 1;
        break;
      }
      printf(str);
    }
    else
    {
      str = ((char **)f->esp)[2];
      number = ((int *)f->esp)[3];
      if(!validate_string(str,number) && thread_current()->fd[fd]==NULL)
      {
        f->eax = 1;
        break;
      }
      file_write(thread_current()->fd[fd], str, number);
    }
    
    f->eax = 0;
    break;
  }

  thread_exit();
}