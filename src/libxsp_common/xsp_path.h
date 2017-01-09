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
#ifndef XSP_PATH_H
#define XSP_PATH_H

#include "xsp_session.h"
#include "xsp_pathrule.h"

enum xsp_path_status_t {
  XSP_PATH_ALLOCATED = 0,
  XSP_PATH_APPLIED,
  XSP_PATH_MIXED
};

typedef struct xsp_path_t {
  char *gri;
  char *description;
  int status;

  struct xsp_pathrule_t **rules;
  int rule_count;
} xspPath;

int xsp_path_init();
xspPath *xsp_alloc_path();
void xsp_free_path(xspPath *path);
int xsp_get_path(xspNetPath *net_path, xspSettings *settings, xspPath **ret_path, char **error_msg);
int xsp_delete_path(xspPath *path);

#endif
