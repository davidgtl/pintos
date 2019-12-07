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
	int crt_time;
	
	crt_time=get_current_ticks();
	
	printf("BEFORE SLEEP: Current time is: %d [ticks]\n", crt_time);
		
	thread_sleep(100);

	crt_time=get_current_ticks();
	
	printf("AFTER SLEEP: Current time is: %d [ticks]\n", crt_time);

	return EXIT_SUCCESS;
}


