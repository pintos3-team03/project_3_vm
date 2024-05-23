/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "include/vm/uninit.h"
#include <string.h>

#define ONE_MB (1 << 20)

struct list frame_table;

static unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
static bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
static void page_destory(struct hash_elem *del, void *hash);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* 할 일: 페이지를 생성하고, VM 타입에 따라 초기화자를 가져옵니다.
		* 그리고 나서 uninit_new를 호출하여 "uninit" 페이지 구조체를 생성합니다.
		* uninit_new를 호출한 후에 필드를 수정해야 합니다. */
		struct page *new_page = malloc(sizeof(struct page));
		if (!new_page)
			return false;

		bool (*page_initializer)(struct page *, enum vm_type, void *);
		switch (VM_TYPE(type))
		{
			case VM_ANON:
				page_initializer = anon_initializer;
				break;
			case VM_FILE:
				page_initializer = file_backed_initializer;
				break;
		}

		uninit_new(new_page, upage, init, type, aux, page_initializer);

		new_page->writable = writable;
		new_page->pml4 = thread_current()->pml4;
		if (!spt_insert_page(spt, new_page)) {
			free(new_page);
			return false;
		}
		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page page;
	page.va = pg_round_down(va);
	struct hash_elem *test = hash_find(&spt->spt_table, &page.hash_elem);
	
	if (test == NULL) {
		return NULL;
	}

	return hash_entry(test, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;

	if (!hash_insert(&spt->spt_table, &page->hash_elem))
		succ = true;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	struct list_elem *e = list_begin(&frame_table);
	for (e; e != list_end(&frame_table); e = list_next(e)) {
		victim = list_entry(e, struct frame, frame_elem);
		
		// second-chance 알고리즘
		if (pml4_is_accessed(victim->page->pml4, victim->page->va))
			pml4_set_accessed(victim->page->pml4, victim->page->va, false);
		else
			return victim;
	}

	return list_entry(list_begin(&frame_table), struct frame, frame_elem);
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if (victim->page)
		swap_out(victim->page);
	victim->page = NULL;
	memset(victim->kva, 0, PGSIZE);

    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* palloc()과 프레임을 가져온다. 항상 유효한 주소를 반환한다. 
 * 사용자 풀 메모리가 가득 찬 경우 사용 가능한 메모리 공간을 얻기 위해 프레임을 제거한다.
 * palloc_get_page 함수를 호출하여 메모리 풀에서 새로운 물리메모리 페이지를 가져온다. 
 * 성공적으로 가져오면 프레임을 할당하고 프레임 구조체의 멤버들을 초기화한 후 해당 프레임을 반환한다.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = calloc(1, sizeof(struct frame));
	void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kva == NULL) {
		free(frame);
		frame = vm_evict_frame();
	} else {
		frame->kva = kva;
		list_push_back(&frame_table, &frame->frame_elem);
	}
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void *stack_bottom = thread_current()->stack_bottom;

    while (stack_bottom > addr) {
        stack_bottom = (void *)(((uint8_t *)stack_bottom) - PGSIZE);

        if (!vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1))
            return;

        if (!vm_claim_page(stack_bottom))
            return;
    }
    thread_current()->stack_bottom = stack_bottom;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */

    if (not_present) { // frame없어

        if (thread_current()->stack_bottom > addr && addr > USER_STACK - (1 << 20)) { // Are you stack? page 없어?
            void *user_rsp = thread_current()->user_rsp;
            if (user)
                user_rsp = f->rsp;
            if (user_rsp == addr || user_rsp - 8 == addr) {
                vm_stack_growth(addr);
                return true;
            }
            return false;
        }

        page = spt_find_page(spt, addr);
        if (!page) {      // page 없어, frame 없어
            return false; // ㄹㅇ 폴트
        }

        return vm_do_claim_page(page); // page찾으면 레이지로딩
    }

    /* TODO: Your code goes here */
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	struct thread *curr = thread_current();
	
	/* TODO: Fill this function */
	page = spt_find_page(&curr->spt, va);
	if (page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *curr = thread_current();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(curr->pml4, page->va, frame->kva, page->writable); // (va - pa) mapping

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_table, page_hash, page_less, NULL);
}

/* 가상 주소에 대한 해시 값을 구하는 함수 */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* 해시 테이블 내 두 페이지 요소에 대한 주소 값을 비교하는 함수 */
static bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	return a->va < b->va;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	hash_first(&i, &src->spt_table);
	while (hash_next(&i))
	{
		// src_page 정보
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		bool writable = src_page->writable;

		/* 1) type이 uninit이면 */
		if (VM_TYPE(type) == VM_UNINIT)
		{ // uninit page 생성 & 초기화
			vm_initializer *init = src_page->uninit.init;
			void *aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
			continue;
		}

		/* 2) type이 file이면 */
		if (VM_TYPE(type) == VM_FILE)
		{
			struct load_segment_aux *file_aux = malloc(sizeof(struct load_segment_aux));
			file_aux->file = src_page->file.file;
			file_aux->ofs = src_page->file.ofs;
			file_aux->read_bytes = src_page->file.read_bytes;
			file_aux->zero_bytes = src_page->file.zero_bytes;
			if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, file_aux))
				return false;
			struct page *file_page = spt_find_page(dst, upage);
			file_backed_initializer(file_page, type, NULL);
			file_page->frame = src_page->frame;
			pml4_set_page(thread_current()->pml4, file_page->va, src_page->frame->kva, src_page->writable);
			continue;
		}

		/* 3) type이 anon이면 */
		if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
			return false;						   // init이랑 aux는 Lazy Loading에 필요. 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음

		// vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
		if (!vm_claim_page(upage))
			return false;

		// 매핑된 프레임에 내용 로딩
		struct page *dst_page = spt_find_page(dst, upage);
		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
static void
page_destory(struct hash_elem *del, void *hash) {
	struct page *delete_page = hash_entry(del, struct page, hash_elem);
    // if (delete_page)
    vm_dealloc_page(delete_page);
}

void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_table, page_destory);
}
