#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "vm/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

#ifndef VM
bool is_valid_address(void *addr) {
    struct thread *curr = thread_current();
    if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
        return false;
	return true;
}
#else
struct page *is_valid_address(void *addr) {
    struct thread *curr = thread_current();
	char temp = *(char *)addr;

    if (is_kernel_vaddr(addr) || addr == NULL)
        return NULL;

    return spt_find_page(&curr->spt, addr);
}

/* 버퍼 유효성 검사 */
void check_valid_buffer(void *buffer, size_t size, bool writable) {
    for (size_t i = 0; i < size; i++) {
        /* buffer가 spt에 존재하는지 검사 */
        struct page *page = is_valid_address(buffer + i);

        if (!page || (writable && !(page->writable)))
            exit(-1);
    }
}
#endif

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	struct thread *curr = thread_current();
	#ifdef VM
	curr->user_rsp = f->rsp;
	#endif

	if (!is_valid_address(f->rsp)) 
		thread_exit();

	switch (f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			thread_exit();
			break;
		case SYS_FORK:
			memcpy(&curr->parent_if, f, sizeof(struct intr_frame));
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
			break;
		default:
			thread_exit ();
	}
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;

	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

pid_t fork (const char *thread_name) {
	if (!is_valid_address(thread_name))
		exit(-1);
	return process_fork(thread_name, &thread_current()->parent_if);
}

int exec (const char *file) {
	if (!is_valid_address(file))
		exit(-1);
		
	char *file_name = palloc_get_page(PAL_ZERO);
	if (file_name == NULL)
		exit(-1);

	memcpy(file_name, file, strlen(file) + 1);
	if (process_exec(file_name) == -1)
		exit(-1);
	return 0;
}

int wait (pid_t child_tid) {
	return process_wait(child_tid);
}

bool
create (const char *file, unsigned initial_size) {
	if (!file || !is_valid_address(file))
		exit(-1);

	lock_acquire(&filesys_lock);
	if (filesys_create(file, initial_size)) {
		lock_release(&filesys_lock);
		return true;
	}

	lock_release(&filesys_lock);
	return false;
}

bool
remove (const char *file) {
	if (!file || !is_valid_address(file))
		exit(-1);

	lock_acquire(&filesys_lock);
	if (filesys_remove(file)) {
		lock_release(&filesys_lock);
		return true;
	}

	lock_release(&filesys_lock);
	return false;
}

int
open (const char *file) {
	if (!file || !is_valid_address(file))
		exit(-1);

	struct thread *curr = thread_current();
	struct file *open_file;

	if (curr->fd_max >= FD_MAX)
		return -1;

	lock_acquire(&filesys_lock);
	if (open_file = filesys_open(file)) {
		for (int idx = curr->fd_max; idx < FD_MAX; idx++) { // 디스크립터 테이블에 open_file 저장
			if (curr->fd_table[idx] == NULL) {
				curr->fd_table[idx] = open_file;
				curr->fd_max = idx;
				lock_release(&filesys_lock);
				return curr->fd_max;
			}
		}
		file_close(open_file);
		curr->fd_max = FD_MAX;
	}
	lock_release(&filesys_lock);
	return -1;
}

int filesize (int fd) {
	if (!fd || fd > FD_MAX)
		exit(-1);
	
	struct file *open_file = thread_current()->fd_table[fd];
	if (open_file) {
		return file_length(open_file);
	}
	return -1;
}

int read (int fd, void *buffer, unsigned length) {
	#ifdef VM
    	check_valid_buffer(buffer, length, true);
	#endif
	if (fd < 0 || fd >= FD_MAX || !is_valid_address(buffer))
		exit(-1);

	struct page *page = spt_find_page(&thread_current()->spt, buffer);
	if (page->writable == 0)
		exit(-1);

	lock_acquire(&filesys_lock);
	if (fd == 0) {
		int count = 0;
		char *temp_buf = buffer;
		for (int i = 0; i < length; i++) {
			*temp_buf = input_getc();
			count++;
			if (*temp_buf == '\0')
				break;
			temp_buf++;
		}
		lock_release(&filesys_lock);
		return count;
	}
	if (fd == 1) {
		lock_release(&filesys_lock);
		exit(-1);
	}
	struct file *open_file = thread_current()->fd_table[fd];
	if (open_file) {
		off_t read_bytes = file_read(open_file, buffer, length);
		lock_release(&filesys_lock);
		return read_bytes;
	}
	lock_release(&filesys_lock);
	return -1;
}

int
write (int fd, const void *buffer, unsigned length) {
	#ifdef VM
    check_valid_buffer(buffer, length, false);
	#endif
	if (fd < 0 || fd >= FD_MAX || !is_valid_address(buffer))
		exit(-1);

	lock_acquire(&filesys_lock);
	if (fd == 1) {
		putbuf(buffer, length);
		lock_release(&filesys_lock);
		return length;
	}

	struct file *open_file = thread_current()->fd_table[fd];
	if (open_file) {
		off_t written_bytes = file_write(open_file, buffer, length);
		lock_release(&filesys_lock);
		return written_bytes;
	}
	lock_release(&filesys_lock);
	return -1;
}

void seek (int fd, unsigned position) {
	if (!fd || fd > FD_MAX) 
		exit(-1);
	
	struct file *open_file = thread_current()->fd_table[fd];
	if (open_file)
		file_seek(open_file, position);
}

unsigned tell (int fd) {
	if (!fd || fd > FD_MAX) 
		exit(-1);
	
	struct file *open_file = thread_current()->fd_table[fd];
	if (open_file)
		file_tell(open_file);
}

void
close (int fd) {
	struct file *curr_file;
	if (!fd || fd > FD_MAX) 
		exit(-1);

	lock_acquire(&filesys_lock);
	curr_file = thread_current()->fd_table[fd];
	if (curr_file) {
		thread_current()->fd_table[fd] = NULL;
		file_close(curr_file);
	}
	lock_release(&filesys_lock);
}

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	if (filesize(fd) <= 0 || length <= 0)
		return NULL;
	if (fd <= 2) // 표준 입출력 디스크립터 일 때
		return NULL;
	if (!addr || addr != pg_round_down(addr)) // addr이 페이지 정렬이 아닐 때
		return NULL;
	if (spt_find_page(&thread_current()->spt, addr)) // 기존에 매핑된 페이지랑 addr이 겹칠 때
		return NULL;
	if (offset != pg_round_down(offset) || offset % PGSIZE != 0)
        return NULL;

	// 커널 영역 접근 방지 (첫 번째 커널 주소 확인)
    if (is_kernel_vaddr(addr))
        return NULL;

    // 커널 영역 접근 방지 (끝 주소가 커널 주소인지 확인)
    void *end_addr = (void *)((size_t)addr + length);
    if (is_kernel_vaddr(end_addr))
        return NULL;

	if (fd >= FD_MAX || thread_current()->fd_table[fd] == NULL)
        return NULL;	
		
	struct file *open_file = thread_current()->fd_table[fd];
	if (open_file == NULL || file_length(open_file) == 0 || (long)length <= 0)
		return NULL;

	// 기존에 매핑된 페이지와 겹치는지 확인
    for (void *page_addr = addr; page_addr < end_addr; page_addr += PGSIZE) {
        if (spt_find_page(&thread_current()->spt, page_addr))
            return NULL;
    }
		
	return do_mmap(addr, length, writable, open_file, offset);
}

void
munmap (void *addr) {
	do_munmap(addr);
}