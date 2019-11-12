#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
	printf ("system call kernel \n");

	int nr = (int)((int*)f->esp)[0];
	int _wfd,_wsize;
	char* _wbuffer;
	switch (nr)
	{
	case SYS_WRITE:
			_wfd = (int)((int*)f->esp)[1];
			_wbuffer = (char*)((int*)f->esp)[2];
			_wsize = (int)((int*)f->esp)[2];
			if(_wfd == 1){
				printf(_wbuffer);
			}
			f->eax = _wsize;
		break;
	case 666:
		printf("Hello from hello");
		break;
	
	default:
		break;
	}


	thread_exit ();
}
