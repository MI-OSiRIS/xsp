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
#ifndef XSP_PATHRULE_H
#define XSP_PATHRULE_H

#include "xsp_session.h"
#include "xsp_path.h"
#include "xsp_pathrule.h"

typedef struct xsp_pathrule_t {
  pthread_mutex_t lock;
  pthread_cond_t timeout_cond;

  struct xsp_addr eid;
  struct xsp_sess_net_path_rule_crit_t crit;
  char *description;
  int tag;
  int status;
  int op;

  int (*apply) (struct xsp_pathrule_t *rule, int action, char **ret_error_msg);
  void (*free) (struct xsp_pathrule_t *rule);

  struct xsp_path_t *path;
  void *private;
} xspPathRule;

xspPathRule *xsp_alloc_pathrule();
void xsp_free_pathrule(xspPathRule *pathrule);

#endif
