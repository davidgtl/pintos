#ifndef _FRAME_C_
#define _FRAME_C_

#include "spte.h"
#include "threads/palloc.h"

struct frame_entry
{
	struct supl_pte* spte;
    struct thread*   ownner_thread;
};

void frame_table_init(size_t number_of_user_pages);

void *frame_alloc( enum palloc_flags flags,  struct supl_pte* spte);
void frame_free(void *frame_addr);

void frame_evict( void *kernel_va);	/* the kernel mode address corresponding to the frame to be evicted */
void * frame_swap_in(struct supl_pte* spte);

#endif
