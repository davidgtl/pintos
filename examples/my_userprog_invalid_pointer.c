/*
 * my_userprog_test.c
 *
 *  Created on: Nov 11, 2012
 *      Author: acolesa
 */


#include <stdio.h>
#include <syscall.h>

#define PHYS_BASE 0xc0000000     /* 3 GB. */

int
main (int argc, char **argv)
{
	int *p;

	// case 1
	p = 0;		// NULL pointer

	// case 2
	// p = PHYS_BASE + 1;	// pointer in the kernel space

	// pointer usage
	*p = 10;

	return EXIT_SUCCESS;
}


