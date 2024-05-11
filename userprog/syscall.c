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

bool
is_valid_address(void *addr) {
	if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL) 
		return false;
	return true;
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// 유저 프로그램이 전달한 포인터가 유효한 주소 범위인지 확인
	struct thread *curr = thread_current();
	// curr->parent_if = *f; // syscall_handler의 인자 intr_frame이 부모의 유저 모드 intr_frame

	if (!is_valid_address(f->rsp)) 
		thread_exit();

	// TODO: 인자 값 넣어주기
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
	thread_current()->exit_status = status;
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
	// 이름을 file로 하고, 크기는 initial_size인 파일 생성
	// 성공적으로 생성하면 true
	if (!file || !is_valid_address(file))
		exit(-1);

	if (filesys_create(file, initial_size)) 
		return true;
	return false;
}

bool
remove (const char *file) {
	// 이름이 file인 파일 삭제 (무조건 삭제)
	if (!file || !is_valid_address(file))
		exit(-1);

	if (filesys_remove(file)) {
		return true;
	}
	return false;
}

int
open (const char *file) {
	if (!file || !is_valid_address(file))
		exit(-1);

	// 이름이 file인 파일을 정상적으로 잘 열었으면 파일 식별자(fd) 반환
	struct thread *curr = thread_current();
	struct file *open_file;

	if (curr->fd_max >= FD_MAX)
		return -1;

	lock_acquire(&filesys_lock);
	if (open_file = filesys_open(file)) {
		// 디스크립터 테이블에 open_file 저장
		for (int idx = curr->fd_max; idx < FD_MAX; idx++) {
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
	if (open_file) 
		return file_length(open_file);
	return -1;
}

int read (int fd, void *buffer, unsigned length) {
	if (!fd || fd > FD_MAX || !is_valid_address(buffer))
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
	if (!fd || fd > FD_MAX || !is_valid_address(buffer))
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

	curr_file = thread_current()->fd_table[fd];
	thread_current()->fd_table[fd] = NULL;
	file_close(curr_file);
}