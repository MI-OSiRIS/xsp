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
#ifndef XSP_TPOOL_H
#define XSP_TPOOL_H

int xsp_tpool_init();
int xsp_tpool_exec(void *(*fn) (void *), void *arg);

#endif
