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
#ifndef HASHTABLE_UTIL_H
#define HASHTABLE_UTIL_H

#include <stdint.h>

#define HASHLITTLE_INIT_VAL 635828137U

unsigned int xsp_hash_string(const void *key);
int xsp_equalkeys_string(const void *k1, const void *k2);

/* hash functions by Bob Jenkins (see hashtable_hashfn.c) */
uint32_t hashword(const uint32_t *k, size_t length, uint32_t initval);
void hashword2 (const uint32_t *k, size_t length, uint32_t *pc, uint32_t *pb);
uint32_t hashlittle( const void *key, size_t length, uint32_t initval);
void hashlittle2(const void *key, size_t length, uint32_t *pc, uint32_t *pb);
uint32_t hashbig( const void *key, size_t length, uint32_t initval);

#endif
