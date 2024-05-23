/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */
#include <bitmap.h>
#include <string.h>
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
	swap_disk = disk_get(1, 1); // Get swap disk
	slot_max = disk_size(swap_disk) / SLOT_SIZE;
	swap_table = bitmap_create(slot_max);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	struct uninit_page *uninit = &page->uninit;
	memset(uninit, 0, sizeof(struct uninit_page));

	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->slot = BITMAP_ERROR;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	size_t slot_idx = anon_page->slot;

	if (slot_idx == BITMAP_ERROR || !bitmap_test(swap_table, slot_idx)) // 스왑 슬롯이 진짜 사용 중인지 체크
		return false;

	for (int i = 0; i < SLOT_SIZE; i++)
		disk_read(swap_disk, (slot_idx * SLOT_SIZE) + i, kva + (DISK_SECTOR_SIZE * i));

	bitmap_set(swap_table, slot_idx, false);
	
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	// 스왑 테이블에서 사용 가능한 스왑 슬롯 찾기
	size_t free_idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
	if (free_idx == BITMAP_ERROR)
		return false;
	// 페이지 크기는 4096바이트, 섹터 크기는 512바이트라 8개의 섹터에 페이지를 넣어야 함
	for (int i = 0; i < SLOT_SIZE; i++)
		disk_write(swap_disk, (free_idx * SLOT_SIZE) + i, page->frame->kva + (DISK_SECTOR_SIZE * i));

	anon_page->slot = free_idx;

	bitmap_set(swap_table, free_idx, true);
	// 페이지와 프레임의 매핑 끊기
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	// struct anon_page *anon_page = &page->anon;

	// if (anon_page->slot != BITMAP_ERROR)
	// 	bitmap_reset(swap_table, anon_page->slot);

	// if (page->frame) {
	// 	list_remove(&page->frame->frame_elem);
	// 	free(page->frame);
	// 	page->frame = NULL;
	// }
	// pml4_clear_page(thread_current()->pml4, page->va);
}
