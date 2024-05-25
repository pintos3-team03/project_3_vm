/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */
#include <bitmap.h>
#include "vm/vm.h"
#include "devices/disk.h"
#include "include/threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

struct bitmap *swap_table;
size_t slot_max;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
    slot_max = disk_size(swap_disk) / SLOT_SIZE;
    swap_table = bitmap_create(slot_max);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	struct uninit_page *uninit = &page->uninit;
	memset(uninit, 0, sizeof(struct uninit_page));
	
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->slot = BITMAP_ERROR;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	size_t slot = anon_page->slot;
	size_t sector_num = slot * SLOT_SIZE;
	if (slot == BITMAP_ERROR || !bitmap_test(swap_table, slot))
		return false;

	// 스왑 디스크의 내용을 메모리로 읽는다.
	for (int i = 0; i < SLOT_SIZE; i++)
		disk_read(swap_disk, sector_num + i, kva + i * DISK_SECTOR_SIZE);
	
	bitmap_set(swap_table, slot, false);
	
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	// page에 연결된 프레임을 디스크로 옮긴다.
	// 1. 스왑 테이블에서 옮길 수 있는 스왑 슬롯 찾기
	size_t free_idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
	if (free_idx == BITMAP_ERROR)
		return false; // 디스크에 여유 스왑 슬롯이 없으면 PANIC 
	size_t sector_num = free_idx * SLOT_SIZE;
	
	// 2. 페이지의 데이터를 스왑 슬롯에 복사
	for (int i = 0; i < SLOT_SIZE; i++)
		disk_write(swap_disk, sector_num + i, page->frame->kva + i * DISK_SECTOR_SIZE);

	anon_page->slot = free_idx;

	// 3. pml4에서 page->va와 page->frame->kva의 연결을 끊는다.
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(page->pml4, page->va);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	if (anon_page->slot != BITMAP_ERROR)
		bitmap_reset(swap_table, anon_page->slot);

	if (page->frame) {
		list_remove(&page->frame->frame_elem);
		palloc_free_page(page->frame->kva);
		free(page->frame);
		page->frame = NULL;
	}
	
	pml4_clear_page(page->pml4, page->va);
}
