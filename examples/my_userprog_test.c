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
	//printf("Hello world!\n");
	write(1, "Hello world!\n", 13); 

	return EXIT_SUCCESS;
}


