#include <stdlib.h>
#include <strings.h>

#include "compat.h"
#include "libxsp_block.h"

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

void xsp_block_add(xspBlock *block, xspBlock *new_block) {
	if (!block->next) {
		block->next = new_block;
		new_block->prev = block;
	}
	else {
		new_block->next = block->next;
		new_block->prev = block;
		block->next->prev = new_block;
		block->next = new_block;
	}
}

void xsp_block_del(xspBlock *block) {
	if (block->next && block->prev) {
		block->next->prev = block->prev;
		block->prev->next = block->next;
	}
	else if (block->prev)
		block->prev->next = NULL;
	else if (block->next)
		block->next->prev = NULL;

	xsp_free_block(block);
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
