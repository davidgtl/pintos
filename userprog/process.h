#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#include <stdint.h>
#include "filesys/file.h"
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (int);
void process_activate (void);
void unload_segment(struct file * f);
bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

struct supl_pte {		// an entry (element) in the supplemental page table
	uint32_t	virt_page_no; 			// the number of the virtual page (also the hash key) having info about
	void*		virt_page_addr;			// the virtual address of the page
	off_t 		ofs;					// the offset in file the bytes to be stored in the page must be read from
	size_t 		page_read_bytes;		// number of bytes to read from the file and store in the page
	size_t 		page_zero_bytes; 		// number of bytes to zero in the page
	bool		writable;				// indincate if the page is writable or not
	struct file* src_file; 
	struct hash_elem he;				// element to insert the structure in a hash list
};
#endif /* userprog/process.h */
