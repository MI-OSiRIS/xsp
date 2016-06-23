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
#include <string.h>

#include "xsp_common.h"

int id_equal_fn( const void *k1, const void *k2) {
	const char *id1 = k1;
	const char *id2 = k2;

	return (strcasecmp(id1, id2) == 0);
}

unsigned int id_hash_fn( const void *k1 ) {
	const char *id = k1;
	unsigned int s = 0;

	while(*id) {
		s += *id;
		id++;
	}

	return s;
}
