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
	
	read(0, &c, sizeof(char));
	write(1, &c, sizeof(char)); 

	printf("\n");
	scanf("%c", &c);
	printf("c=%c\n", c);

	return EXIT_SUCCESS;
}


