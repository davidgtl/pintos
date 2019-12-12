#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/spte.h"

#include <stdint.h>
#include "filesys/file.h"
#include "lib/kernel/hash.h"
#include "filesys/file.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (int);
void process_activate (void);
void unload_segment(struct file * f);
bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
struct supl_pte *page_lookup(const void *);
bool load_page_for_address(uint8_t *upage);
bool lazy_loading_page_for_address(	struct supl_pte *spte, void *upage);
#endif /* userprog/process.h */