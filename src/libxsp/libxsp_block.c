#include <stdlib.h>
#include <strings.h>

#include "compat.h"
#include "libxsp_block.h"

xspBlockList *xsp_alloc_block_list() {
	xspBlockList *new_bl;
	
	new_bl = malloc(sizeof(xspBlockList));
	if (!new_bl)
		goto error_exit;
	
	bzero(new_bl, sizeof(xspBlockList));

	return new_bl;

 error_exit:
	return NULL;
}

void xsp_free_block_list(xspBlockList *bl) {
	xspBlock *block;
	for (block = bl->first; block != NULL; block = block->next)
		xsp_free_block(block);

	free(bl);
}		

void xsp_block_list_push(xspBlockList *bl, xspBlock *new_block) {
	if (!bl->first) {
		bl->first = new_block;
		bl->last = new_block;
		new_block->next = NULL;
		new_block->prev = NULL;
	}
	else {
		new_block->next = bl->first;
		new_block->prev = NULL;
		bl->first->prev = new_block;
		bl->first = new_block;
	}
	bl->count++;
}

xspBlock *xsp_block_list_pop(xspBlockList *bl) {
	xspBlock *ret;

	ret = bl->first;
	
	if (bl->count > 1) {
		bl->first = bl->first->next;
		bl->first->prev = NULL;
		bl->count--;
	}
	else if (bl->count == 1) {
		bl->first = NULL;
		bl->last = NULL;
		bl->count--;
	}
	
	return ret; 
}

inline int xsp_block_list_get_count(xspBlockList *bl) {
	return bl->count;
}

xspBlock *xsp_alloc_block() {
	xspBlock *new_block;

	new_block = malloc(sizeof(xspBlock));
	if (!new_block)
		goto error_exit;

	bzero(new_block, sizeof(xspBlock));

	return new_block;

error_exit:
	return NULL;
}

void xsp_free_block(xspBlock *block) {
	if (block->data)
		free(block->data);

	free(block);
}

inline void xsp_block_set_data(xspBlock *block, void *data) {
	block->data = (void*)data;
}

inline void xsp_block_set_type(xspBlock *block, int type) {
	block->type = type;
}

inline void xsp_block_set_sport(xspBlock *block, int sport) {
	block->sport = sport;
}

inline void xsp_block_set_length(xspBlock *block, uint64_t len) {
	block->length = len;
}

inline void *xsp_block_get_data(xspBlock *block) {
	return block->data;
}

inline int xsp_block_get_type(xspBlock *block) {
	return block->type;
}

inline int xsp_block_get_sport(xspBlock *block) {
	return block->sport;
}

inline uint64_t xsp_block_get_length(xspBlock *block) {
	return block->length;
}
