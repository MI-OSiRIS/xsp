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
#ifndef XSP_TERAPATHS_BASIC_H
#define XSP_TERAPATHS_BASIC_H

#include <pthread.h>

#define TPS_DOWN            0x00
#define TPS_UP		    0x01
#define TPS_STARTING	    0x02

#define PATH_PRIVATE        0x00
#define PATH_SHARED         0x01

typedef struct xsp_terapaths_path_t {
	xspSoapContext tsc;
	xspSoapContext msc;

	char *src;
	char *dst;

	char *src_ports;
	char *dst_ports;

	char *direction;
	char *bw_class;

	uint64_t bw;
	uint64_t bw_used;
	uint64_t start_time;
	uint64_t duration;

	char *reservation_id;
	char *related_res_ids;
	char *vlan_tag;

	int sleep_time;

	int teardown_timeout;

	int start_offset;
	
	int monitor;
	int type;
	int status;
	pthread_cond_t setup_cond;
} xspTERAPATHSPath;

#endif
