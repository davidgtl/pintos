#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "lib/string.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "vm/swap.h"
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

  if (!is_user_vaddr(p))
    return false;

  if (p == NULL)
    return false;
  if (thread_current()->pagedir == NULL)
    return false;
  return pagedir_get_page(thread_current()->pagedir, p) != NULL;
}

bool validate_string(char *str, int size)
{

  if (str == "")
    return false;

  if (str == NULL)
  {
    process_exit(-1);
  }

  for (char *c = str; c != NULL && c - str <= size; c++)
  {
    if (!validate_pointer(c))
    {
      process_exit(-1);
    }
  }
  return true;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  if ((f->esp > PHYS_BASE - 12 || f->esp < 0) || !validate_pointer(f->esp))
  {
    process_exit(-1);
    return;
  }

  int syscall_no = ((int *)f->esp)[0];
  bool ok;
  int number;
  int fd;
  char c;
  char *str;
  int32_t size;
  void *mapping_addr;
  int iterator;
  int mapping_id;
  uint32_t read_bytes, zero_bytes;

  //printf("syscall-no: %d\n", syscall_no);

  switch (syscall_no)
  {
  case SYS_EXEC:
    str = (char *)((char **)f->esp)[1];
    if (!validate_string(str, PGSIZE))
    {
      f->eax = 1;
      break;
    }
    f->eax = process_execute(str);

    break;
  case SYS_WAIT:
    number = ((int *)f->esp)[1];
    f->eax = process_wait(number);
    break;
  case SYS_EXIT:
    number = ((int *)f->esp)[1];
    process_exit(number);
    f->eax = number;
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
      if (!validate_string(str, number))
      {
        f->eax = -1;
        break;
      }

      if (fd > 30)
        break;
      if (thread_current()->fd[fd] == -1 || thread_current()->fd[fd] == NULL)
      {
        process_exit(-1);
        break;
      }
      else
        f->eax = file_write(thread_current()->fd[fd], str, number);
    }
    break;
  /**case SYS_WRITE:
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
    **/
  case SYS_READ:
    number = ((int *)f->esp)[1];

    if (number == 1)
    {
      process_exit(-1);
      break;
    }
    else if (number == 0)
      f->eax = input_getc();

    else
    {
      str = ((char **)f->esp)[2];
      size = ((int32_t *)f->esp)[3];
      if (!validate_string(str, size) || (number >= 30 || number <= -1))
      {
        f->eax = -1;
        process_exit(-1);
        break;
      }
      if (thread_current()->fd[number] == -1)
        f->eax = -1;
      else
        f->eax = file_read(thread_current()->fd[number], str, size);
    }
    break;
  case SYS_OPEN:
    str = ((char **)f->esp)[1];

    if (str == NULL)
      process_exit(-1);
    if (!validate_string(str, PGSIZE))
    {
      f->eax = -1;
      break;
    }
    else
    {
      struct file *fisier = filesys_open(str);
      if (fisier != NULL)
        for (int i = 3; i < 30; i++)
        {
          if (thread_current()->fd[i] == NULL)
          {
            thread_current()->fd[i] = fisier;
            f->eax = i;
            break;
          }
        }
      else
      {
        f->eax = -1;
      }

      /* code */
    }

    break;
  case SYS_CREATE:

    str = (char *)((char **)f->esp)[1];

    if (str == NULL)
    {
      process_exit(-1);
      break;
    }

    else if (!validate_string(str, PGSIZE / 32))
    {
      f->eax = 0;
      break;
    }
    else

        if (strlen(str) > 400)
    {
      f->eax = 0;
      break;
    }

    else
    {

      size = ((int32_t *)f->esp)[2];
      f->eax = filesys_create(str, size);

      break;
    }
  case SYS_REMOVE:
    str = ((char **)f->esp)[1];
    if (!validate_string(str, PGSIZE))
    {
      f->eax = 1;
      break;
    }
    f->eax = filesys_remove(str);
    break;
  case SYS_SEEK:
    number = ((int *)f->esp)[1];
    if (number >= 30 || number <= -1)
    {
      f->eax = 1;
      break;
    }
    size = ((int32_t *)f->esp)[2];
    file_seek(thread_current()->fd[number], size);
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

    if (thread_current()->fd[number] == NULL || thread_current()->fd[number] == -1)
    {
      process_exit(-1);
      break;
    }

    file_close(thread_current()->fd[number]);
    thread_current()->fd[number] = NULL;

    f->eax = 0;
    break;
  case SYS_MMAP:

    fd = ((int *)f->esp)[1];
    mapping_addr = (void *)((int *)f->esp)[2];

    if (!is_user_vaddr(mapping_addr) || mapping_addr == NULL || mapping_addr == 0)
    {
      f->eax = -1;
      return;
    }
    // Lazy mapping of the file. Similar to lazy loading the contents of an executable file.
    // Calculate the total number of virtual pages needed to map the entire file.
    // Take care that the last page could not be entirely used, so the trailing bytes should be zeroed and not written back in the file.
    // Keep track for each mapped virtual page the offset in file it must be loaded from.
    // Use supplemental page table to store this information.
    // TO DO

    size = file_length(thread_current()->fd[fd]);
    for (iterator = 0; iterator < size; iterator += PGSIZE)
    {
      if (page_lookup(mapping_addr + (int)iterator))
      {

        f->eax = -1;
        return;
      }
    }
    //  printf("SE INCARCA SEGMENTUL \n");
    if (thread_current()->fd[fd] == -1 || thread_current()->fd[fd] == NULL)
    {
      f->eax = -1;
      return;
    }

    load_segment(thread_current()->fd[fd], 0, (void *)mapping_addr,
                 size, PGSIZE - size % PGSIZE, true);
    //printf("fd =  %d \n", fd);
    f->eax = fd;
    return;
  case SYS_MUNMAP:
    fd = ((int *)f->esp)[1];
    // Remove from the supplemental page table the elements corresponding to the unmapped pages.
    // TO DO

    if (fd != -1 && thread_current()->fd[fd] != NULL)
    {
      unload_segment(thread_current()->fd[fd]);
    }

    f->eax = 0;
    return;
  }

  return;
}