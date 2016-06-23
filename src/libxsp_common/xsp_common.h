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
#ifndef XSP_COMMON_H
#define XSP_COMMON_H

enum xsp_direction_t { XSP_INCOMING, XSP_OUTGOING, XSP_BOTH };

int id_equal_fn( const void *k1, const void *k2);
unsigned int id_hash_fn( const void *k1 );

#endif
