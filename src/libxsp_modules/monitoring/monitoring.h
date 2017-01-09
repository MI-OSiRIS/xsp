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
#ifndef MONITORING_H
#define MONITORING_H

#include <stdint.h>
#include "xsp_soap_context.h"


int monitoring_notify(xspSoapContext *mntr, const char *id, const char *src,
                      const char *dst,const char *src_port_range, const char *dst_port_range,
                      const char *vlan_id, const char *direction, uint64_t start_time,
                      uint64_t duration, uint64_t bw,const char *bw_class, const char *status);

int monitoring_set_status(xspSoapContext *mntr, const char *res_id, const char *status);

int monitoring_update_path(xspSoapContext *mntr, const char *res_id, const char *src,
                           const char *dst, const char *src_port_range, const char *dst_port_range,
                           const char *vlan_id, const char *direction, uint64_t start_time,
                           uint64_t duration, uint64_t bw, const char *bw_class, const char *status);

int monitoring_remove(xspSoapContext *mntr, const char *res_id);

#endif
