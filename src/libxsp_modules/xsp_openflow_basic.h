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
#ifndef XSP_OPENFLOW_BASIC_H
#define XSP_OPENFLOW_BASIC_H

#include <pthread.h>

#define OF_CTRL_DOWN		    0x00
#define OF_CTRL_UP		    0x01

struct xsp_openflow_rules_t {
	char **src_list;
	char **dst_list;
	int src_count;
	int dst_count;
};

#endif
