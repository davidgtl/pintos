#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool validate_pointer(void *p)
{
  return is_user_vaddr(p) && p != NULL && pagedir_get_page(thread_current()->pagedir, p) != NULL;
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
  bool ok;
  int number;
  int fd;
  char c;
  char *str;
  int32_t size;

  //printf("syscall-no: %d\n", syscall_no);

  switch (syscall_no)
  {
  case SYS_EXEC:
    str = ((char **)f->esp)[1];
    if (!validate_string(str, PGSIZE))
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
  /*case SYS_WRITE:
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
      if (!validate_string(str, number))
      {
        f->eax = 1;
        break;
      }
      putbuf(str, number);
      f->eax = 0;
    }
    else if (fd == 2)
    {
      str = ((char **)f->esp)[2];
      number = ((int *)f->esp)[3];
      if (!validate_string(str, number))
      {
        f->eax = 1;
        break;
      }
      putbuf(str, number);
      f->eax = 0;
    }
    else
    {
      str = ((char **)f->esp)[2];
      number = ((int *)f->esp)[3];
      if (!validate_string(str, number) && thread_current()->fd[fd] == NULL)
      {
        f->eax = 1;
        break;
      }
      file_write(thread_current()->fd[fd], str, number);
      f->eax = 0;
    }
    break;*/
  case SYS_WRITE:
    number = ((int *)f->esp)[1];
    str = ((char**)f->esp)[2];
    size = ((int32_t *)f->esp)[3];
    if(!validate_string(str,size) || (number >=30 || number <= -1))
    {
      f->eax = -1;
      break;
    }
    f->eax = file_write (thread_current()->fd[number], str, size);
    break;
  case SYS_READ:
    number = ((int *)f->esp)[1];
    str = ((char**)f->esp)[2];
    size = ((int32_t *)f->esp)[3];
    if(!validate_string(str,size) || (number >=30 || number <= -1))
    {
      f->eax = -1;
      break;
    }
    f->eax = file_read (thread_current()->fd[number], str, size);
    break;
  case SYS_OPEN:
    str = ((char **)f->esp)[1];
    if (!validate_string(str, PGSIZE))
    {
      f->eax = 1;
      break;
    }
    struct file *fisier = filesys_open(str);
    for(int i=0;i<30;i++)
    {
      if(thread_current()->fd[i]==NULL)
      {
        thread_current()->fd[i] = fisier;
        f->eax = i;
      }
    }
    f->eax = -1;
    break;
  case SYS_CREATE:
    str = ((char **)f->esp)[1];
    if (!validate_string(str, PGSIZE))
    {
      f->eax = 1;
      break;
    }
    size = ((int32_t *)f->esp)[2];
    ok = filesys_create(str,size);
    if(ok)
    {
      f->eax = 0;
    }
    else
    {
      f->eax = -1;
    }
    break;
  case SYS_REMOVE:
    str = ((char **)f->esp)[1];
    if (!validate_string(str, PGSIZE))
    {
      f->eax = 1;
      break;
    }
    ok = filesys_remove(str);
    if(ok)
    {
      f->eax = 0;
    }
    else
    {
      f->eax = -1;
    }
    break;
  case SYS_SEEK:
    number = ((int *)f->esp)[1];
    if (number >= 30 || number <= -1)
    {
      f->eax = 1;
      break;
    }
    size = ((int32_t *)f->esp)[2];
    file_seek(thread_current()->fd[number],size);
    f->eax = 0;
    break;
  case SYS_FILESIZE:
    number = ((int *)f->esp)[1];
    if (number >= 30 || number <= -1)
    {
      f->eax = 1;
      break;
    }
    f->eax = file_length(thread_current()->fd[number]);
    break;
  case SYS_TELL:
    number = ((int *)f->esp)[1];
    if (number >= 30 || number <= -1)
    {
      f->eax = 1;
      break;
    }
    f->eax = file_tell(thread_current()->fd[number]);
    break;
  case SYS_CLOSE:
    number = ((int *)f->esp)[1];
    if (number >= 30 || number <= -1)
    {
      f->eax = 1;
      break;
    }
    file_close(thread_current()->fd[number]);
    f->eax = 0;
    break; 
  }

  return;
}