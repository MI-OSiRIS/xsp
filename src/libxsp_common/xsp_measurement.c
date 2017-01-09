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
#include <sys/time.h>
#include <stdio.h>

#include "xsp_logger.h"
#include "xsp_measurement.h"

/*
 *  void xsp_log_measurement_dbl(struct timeval time, char *target, char *event, double value):
 *      This function logs a measurement event taken at the specified time on
 *      the specified target.
 */
void xsp_log_measurement_dbl(struct timeval time, char *target, char *event, double value) {
  xsp_log(XSP_MEAS, 0, "(%lu.%lu, %s, %s, %f)", time.tv_sec, time.tv_usec, target, event, value);
}

/*
 *  void xsp_log_measurement_uint(struct timeval time, char *target, char *event, unsigned int value):
 *      This function logs a measurement event taken at the specified time on
 *      the specified target.
 */
void xsp_log_measurement_uint(struct timeval time, char *target, char *event, uint64_t value) {
  xsp_log(XSP_MEAS, 0, "(%lu.%lu, %s, %s, %llu)", time.tv_sec, time.tv_usec, target, event, value);
}

/*
 *  void xsp_log_measurement_str(struct timeval time, char *target, char *event, char *value):
 *      This function logs a measurement event taken at the specified time on
 *      the specified target.
 */
void xsp_log_measurement_str(struct timeval time, char *target, char *event, char *value) {
  xsp_log(XSP_MEAS, 0, "(%lu.%lu, %s, %s, %s)", time.tv_sec, time.tv_usec, target, event, value);
}

