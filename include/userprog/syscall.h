#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "include/lib/user/syscall.h"

bool is_valid_address(void *addr);

void syscall_init (void);

#endif /* userprog/syscall.h */
