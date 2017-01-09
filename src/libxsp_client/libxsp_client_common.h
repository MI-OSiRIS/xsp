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
#ifndef LIBXSP_CLIENT_COMMON_H
#define LIBXSP_CLIENT_COMMON_H

typedef struct libxsp_net_path_rule_crit {
  char *iface;
  char *src;
  char *dst;
  char *src_mask;
  char *dst_mask;
  char *l2_src;
  char *l2_dst;
  uint16_t vlan;
  uint16_t src_vlan;
  uint16_t dst_vlan;
  uint32_t src_port;
  uint32_t dst_port;

  uint64_t bandwidth;
  uint64_t duration;

  // add remaining fields exported to clients
} libxspNetPathRuleCrit;


#endif
