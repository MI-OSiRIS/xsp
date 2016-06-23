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
#ifndef DHPARAMS_H
#define DHPARAMS_H 1

#include <openssl/dh.h>

DH *get_dh1024(void);
DH *get_dh2048(void);
DH *get_dh4096(void);

#endif /* dhparams.h */
