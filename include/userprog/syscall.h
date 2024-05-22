#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "include/lib/user/syscall.h"

#ifndef VM
bool is_valid_address(void *addr);
#else
struct page *is_valid_address(void *addr);
void check_valid_buffer(void *buffer, size_t size, bool writable);
#endif

void syscall_init (void);

#endif /* userprog/syscall.h */
