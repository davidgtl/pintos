#ifndef _SWAP_H_
#define _SWAP_H

#include "devices/block.h"
#include "threads/vaddr.h"
#include <bitmap.h>

/*
 * For the management of the swap partition we are using a bitmap
 * The documentation regarding swap table implementation can be fownd in the
 * Pintos manual chapter 4.1.6 Managing the Swap Table
 */
#define SWAP_SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

#define SWAP_FREE 0      //0 in the bitmap => position is free
#define SWAP_USED 1      //1 in the bitmap => position is in use

extern struct bitmap * swap_table;

void swap_init(void);
void swap_uninit(void);

extern struct block *swap_block;

void swap_in(size_t bitmap_idx, void *frame_addr);
size_t swap_out(void *frame_addr);
block_sector_t swap_block_size ();
const char * swap_block_name ();
unsigned long long swap_read_cnt();
unsigned long long swap_write_cnt();

#endif
