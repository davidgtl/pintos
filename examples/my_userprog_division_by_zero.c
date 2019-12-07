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
	int d;

	d=10/0;

	printf("d=%d\n", d);

	return EXIT_SUCCESS;
}


