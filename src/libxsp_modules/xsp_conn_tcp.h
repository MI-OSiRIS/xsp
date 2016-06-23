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
#ifndef XSP_IO_TCP_H
#define XSP_IO_TCP_H

#include <pthread.h>

#include "xsp_conn.h"

typedef struct xsp_connection_tcp_data_t {
	pthread_mutex_t lock;
	int closed;
	int sd;
} xspConn_tcpData;

xspConn *xsp_conn_tcp_alloc(int sd, int use_web100);

#endif
