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
#ifndef XSP_MEASUREMENT_H
#define XSP_MEASUREMENT_H

#include <stdint.h>

#define XSP_STATS_BYTES_READ		1
#define XSP_STATS_BYTES_WRITTEN		2
#define XSP_STATS_BYTES_RETRANSMITTED	3
#define XSP_STATS_RTT			4
#define XSP_STATS_READ_BANDWIDTH	5
#define XSP_STATS_WRITE_BANDWIDTH	6

void xsp_log_measurement_dbl(struct timeval time, char *target, char *event, double value);
void xsp_log_measurement_uint(struct timeval time, char *target, char *event, uint64_t value);
void xsp_log_measurement_str(struct timeval time, char *target, char *event, char *value);

#endif
