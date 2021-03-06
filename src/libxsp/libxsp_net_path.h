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
#ifndef LIBXSP_NET_PATH_H
#define LIBXSP_NET_PATH_H

#include "xsp-proto.h"

typedef struct xsp_sess_net_path_rule_crit_t {
  // all the supported config criteria
  struct xsp_addr src_eid;
  struct xsp_addr dst_eid;
  struct xsp_addr src_mask;
  struct xsp_addr dst_mask;

  uint64_t src_port;
  uint64_t dst_port;

  uint64_t l2_src;
  uint64_t l2_dst;

  uint16_t l4_src_port_min;
  uint16_t l4_src_port_max;
  uint16_t l4_dst_port_min;
  uint16_t l4_dst_port_max;

  uint16_t vlan;
  uint8_t  vlan_priority;
  uint8_t  dscp;
  uint8_t  dscp_class;
  uint32_t mpls;
  uint32_t mpls_class;
  uint8_t  l3_proto;
  int16_t  l2_type;
  
  // reservation specific
  uint16_t src_vlan;
  uint16_t dst_vlan;
  uint8_t  direction;
  uint64_t bandwidth;
  uint64_t start_time;
  uint64_t end_time;
  uint64_t duration;
} xspNetPathRuleCrit;

typedef struct xsp_sess_net_path_rule_t {
  char                                 type[XSP_NET_PATH_LEN+1];
  uint16_t                             op;
  struct xsp_addr                      eid;
  struct xsp_sess_net_path_rule_crit_t crit;
  uint8_t                              use_crit;
  uint32_t                             data_size;
  char                                 data[];
} xspNetPathRule;

typedef struct xsp_sess_net_path_t {
  uint16_t action;
  struct xsp_sess_net_path_rule_t **rules;
  int rule_count;
} xspNetPath;


xspNetPath *xsp_alloc_net_path();
xspNetPathRule *xsp_alloc_net_path_rule();
xspNetPath *xsp_net_path_new(char *type, int action);
void xsp_net_path_add_rule(xspNetPath *path, xspNetPathRule *rule);

#endif
