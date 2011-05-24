#ifndef LIBXSP_BLOCK_H
#define LIBXSP_BLOCK_H

#ifndef PACKAGE
#include "config.h"
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#include "xsp-proto.h"

typedef struct xsp_block_t {
	int type;
	int sport;
	uint64_t length;
	void *data;
	
	struct xsp_block_t *next;
	struct xsp_block_t *prev;
	int block_count;
} xspBlock;

xspBlock *xsp_alloc_block();
void xsp_free_block(xspBlock *block);

void xsp_block_add(xspBlock *block, xspBlock *new_block);
void xsp_block_del(xspBlock *block);

inline void xsp_block_set_data(xspBlock *block, void *data);
inline void xsp_block_set_type(xspBlock *block, int type);
inline void xsp_block_set_sport(xspBlock *block, int sport);
inline void xsp_block_set_length(xspBlock *block, uint64_t len);

inline void *xsp_block_get_data(xspBlock *block);
inline int xsp_block_get_type(xspBlock *block);
inline int xsp_block_get_sport(xspBlock *block);
inline uint64_t xsp_block_get_length(xspBlock *block);

#endif
