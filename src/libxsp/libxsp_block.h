// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
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

#define XSP_BLOCK_KEEP_DATA 0x00
#define XSP_BLOCK_FREE_DATA 0x01

enum xsp_block_types_t {
  XSP_OPT_NULL = 0,
  XSP_OPT_HOP,
  XSP_OPT_AUTH_TYP,
  XSP_OPT_AUTH_TOK,
  XSP_OPT_NACK,
  XSP_OPT_DATA,
  XSP_OPT_PATH,
  XSP_OPT_SLAB,
  XSP_OPT_APP,
  XSP_OPT_APP_LIST,
};

typedef struct xsp_block_t {
  int type;
  int sport;
  uint64_t length;
  void *data;

  struct xsp_block_t *next;
  struct xsp_block_t *prev;
} xspBlock;

typedef struct xsp_block_list_t {
  struct xsp_block_t *first;
  struct xsp_block_t *last;
  int count;
} xspBlockList;

xspBlock *xsp_alloc_block();
void xsp_free_block(xspBlock *block, int free_data);

xspBlockList *xsp_alloc_block_list();
void xsp_block_list_push(xspBlockList *bl, xspBlock *new_block);
xspBlock *xsp_block_list_pop(xspBlockList *bl);
void xsp_free_block_list(xspBlockList *bl, int free_data);
int xsp_block_list_find(xspBlockList *bl, int type, xspBlock ***ret_ary, int *count);
xspBlock *xsp_block_new(int opt_type, int sport, uint64_t len, const void *data);

inline int xsp_block_list_get_count(xspBlockList *bl) {
  return bl->count;
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

#endif
