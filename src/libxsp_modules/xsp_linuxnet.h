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
#ifndef XSP_LINUXNET_H
#define XSP_LINUXNET_H

#include <pthread.h>

enum xsp_linuxnet_ops_t {
	XSP_LINUXNET_SET_ROUTE,
	XSP_LINUXNET_SET_IP,
	XSP_LINUXNET_SET_VLAN
};

struct xsp_linuxnet_cfg_t {
	char **iface_list;
	int iface_count;
};

char *op_map[3] = {"SET_ROUTE", "SET_IP", "SET_VLAN"};

#endif
