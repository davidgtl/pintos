#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
	int syscall_no = ((int*)f->esp)[0];
	int count;	

	printf ("system call no %d!\n", syscall_no);

	switch (syscall_no) {
		case SYS_EXIT:
			printf ("SYS_EXIT system call!\n");
			thread_exit();
			break;
		case SYS_WRITE:
			printf ("SYS_WRITE system call!\n");
			f->eax=0;
			return;
		case 69:
			count = 0;
			for(unsigned int i = 0x00000000; i <= PHYS_BASE; i += PGSIZE){
				if(is_user_vaddr(i)){
					//printf("AAM: %d\n", pagedir_get_page (thread_current()->pagedir, i));
					if(pagedir_get_page (thread_current()->pagedir, i) != NULL)
						printf("%#010x \n", pagedir_get_page (thread_current()->pagedir, i));
					count += pagedir_get_page (thread_current()->pagedir, i) != NULL;
				}
			}
			printf("Ana are %d mere.\n", count);
			f->eax = count;
			return;
		case 70:
			count = 0;
			for(unsigned int i = PHYS_BASE; i >= 0; i -= PGSIZE){
				if(is_user_vaddr(i)){
					if(pagedir_get_page (thread_current()->pagedir, i) == NULL)
						break;
					count += 1;
				}
			}
			char i = count > 1 ? 'i' : ' ';
			printf("Ana are %d cartof%c\n", count, i);
			f->eax = count;
			return;
	}

	thread_exit ();
}
