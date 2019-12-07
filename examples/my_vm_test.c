/*
 * my_userprog_test.c
 *
 *  Created on: Nov 11, 2012
 *      Author: acolesa
 */


#include <stdio.h>
#include <syscall.h>
#include <string.h>


char *msg = "Hello OSD world!\n";


int
main (int argc, char **argv)
{

	//printf("%s\n", msg);
	write(1, msg, strlen(msg));

	return EXIT_SUCCESS;
}


