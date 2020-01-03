#include "frame.h"
#include <bitmap.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <stdio.h>
#include <string.h>
#include "swap.h"
#include "spte.h"

static struct frame_entry *frame_table;
static void *user_frames = NULL;

#define FRAME_FREE 0
#define FRAME_USED 1
static struct bitmap *free_frames_bitmap;

void frame_table_init(size_t number_of_user_pages)
{
	// allocate an array of frame entries
	// printf("[frame_table] Initialize for %d frames\n", number_of_user_pages);
	frame_table = malloc(number_of_user_pages * sizeof(struct frame_entry));
	if (NULL == frame_table)
	{
		PANIC("Unable to allocate space for the frame table.");
	}
	memset(frame_table, 0, number_of_user_pages * sizeof(struct frame_entry));

	user_frames = palloc_get_multiple(PAL_USER, number_of_user_pages);
	if (NULL == user_frames)
	{
		PANIC("Unable to claim user space for the frame manager.");
	}

	// printf("[frame_table] Claimed %d user frames\n", number_of_user_pages);
	// printf("[frame_table] Address at 0x%X\n", user_frames);

	// initialize a bitmap to represent the free frames
	free_frames_bitmap = bitmap_create(number_of_user_pages);
	if (NULL == free_frames_bitmap)
	{
		PANIC("Unable to initialize swap table!");
	}

	// mark all the indexes in the frame table as free
	bitmap_set_all(free_frames_bitmap, FRAME_FREE);
}

void *frame_alloc(enum palloc_flags flags, struct supl_pte *spte)
{
	ASSERT(0 != (flags & PAL_USER));
	ASSERT(NULL != frame_table);
	ASSERT(NULL != free_frames_bitmap);

	// find the first free frame;
	size_t free_idx = 0;

	free_idx = bitmap_scan_and_flip(free_frames_bitmap, 0, 1, FRAME_FREE);
	if (BITMAP_ERROR == free_idx)
	{
		PANIC("[frame_table] Table is full.");
		// TODO: evict a page and install a new one
		uint8_t *kpage;

		
		frame_evict(kpage);
		
		// Added by Adrian Colesa - Userprog + VM
		//printf("[load_segment] The process virtual page %d starting at virtual address 0x%x will be mapped onto the kernel virtual page %d (physical frame %d) starting at kernel virtual address 0x%x (physical address 0x%x)\n", ((unsigned int) upage)/PGSIZE, upage, (unsigned int)kpage/PGSIZE, ((unsigned int)vtop(kpage))/PGSIZE, kpage, vtop(kpage));
		//printf("[load_segment] Virtual page %d (vaddr=0x%x): mapped onto the kernel virtual page %d (physical frame %d)\n", ((unsigned int) upage)/PGSIZE, upage, (unsigned int)kpage/PGSIZE, ((unsigned int)vtop(kpage))/PGSIZE);

		/* Add the page to the process's address space. */
		/*if (!install_page(upage, kpage, writable))
		{
			palloc_free_page(kpage);
			return false;
		}*/
	}
	// printf("[frame_table] Allocated frame with index = %d\n", free_idx);

	frame_table[free_idx].spte = spte;
	frame_table[free_idx].ownner_thread = thread_current();
	frame_table[free_idx].spte->frame_entry = &frame_table[free_idx];

	if (0 != (PAL_ZERO & flags))
	{
		memset((char *)user_frames + PGSIZE * free_idx, 0, PGSIZE);
	}

	//frame_evict(free_idx);

	return (char *)user_frames + PGSIZE * free_idx;
}

void frame_evict(void *kernel_va)
{
	ASSERT(NULL != frame_table);
	ASSERT(NULL != free_frames_bitmap);

	// HINT: Compute the frame_index for the kernel_va, see frame_free
	// HINT: struct supl_pte * spte = frame_table[frame_idx].spte;

	size_t idx = ((size_t)kernel_va - (size_t)user_frames) / PGSIZE;
	struct supl_pte *spte = frame_table[idx].spte;
	size_t swap_idx = swap_out(kernel_va);
	spte->swapped_out = true;
	spte->swap_idx = swap_idx;
	frame_free(spte->virt_page_addr);
	//palloc_free_page(spte->virt_page_addr);

	// swap the frame out, mark the spte as swapped out.
	// mark the entry as free
}

void *frame_swap_in(struct supl_pte *spte)
{
	ASSERT(NULL != frame_table);
	ASSERT(NULL != free_frames_bitmap);

	// find the first free frame and mark it as used
	size_t free_idx = spte->swap_idx;

	swap_in(free_idx, spte->virt_page_addr);

	// swap in
	return (char *)user_frames + PGSIZE * free_idx;
}

void frame_free(void *frame_addr)
{
	ASSERT(frame_addr >= user_frames);
	ASSERT(NULL != frame_table);
	ASSERT(NULL != free_frames_bitmap);

	size_t idx = ((size_t)frame_addr - (size_t)user_frames) / PGSIZE;

 //   printf("[frame_table] Free frame with index = %d\n", idx);
	bitmap_set(free_frames_bitmap, idx, FRAME_FREE);
}
