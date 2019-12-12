#ifndef _SPTE_H_
#define _SPTE_H_

// Added by Adrian Colesa - VM
#include <stdint.h>
#include "filesys/file.h"
#include "hash.h"

// Added by Adrian Colesa - VM
struct supl_pte {		// an entry (element) in the supplemental page table
	uint32_t	virt_page_no; 			// the number of the virtual page (also the hash key) having info about
	void*		virt_page_addr;			// the virtual address of the page
	off_t 		ofs;					// the offset in file the bytes to be stored in the page must be read from
	size_t 		page_read_bytes;		// number of bytes to read from the file and store in the page
	size_t 		page_zero_bytes; 		// number of bytes to zero in the page
	bool		writable;				// indincate if the page is writable or not
	struct hash_elem he;				// element to insert the structure in a hash list
	bool        swapped_out;            // corresponds to a swapped out page
    size_t      swap_idx;               // index for swap in
};

#endif
