/*
 * my_userprog_test.c
 *
 *  Created on: Nov 11, 2012
 *      Author: acolesa
 */


#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
	char c;
	
	
	halt();
	
	int pid_cild = exec("child.exe");
	wait(pid_child);
	
	create("file");
	remove("file");
	int fd = open("file");
	int size = filesize(fd);
	read(fd, &c, sizeof(c));
	write(fd, &c, sizeof(c)); 
	seek(fd, 0);
	int pos = tell(fd);
	close(fd);
	
	return EXIT_SUCCESS;
}


