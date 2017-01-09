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
#ifndef XSP_AUTH_PASS_H
#define XSP_AUTH_PASS_H

typedef struct xsp_pass_user_info_t {
  char *username;
  char *password;
  char *email;
  char *institution;
  int activated;
} xspPassUserInfo;

typedef struct xsp_pass_backend_t {
  char *name;
  xspPassUserInfo *(*get_user_info)(const char *username);
} xspPassBackend;

int xsp_set_pass_backend(xspPassBackend *be);
xspPassUserInfo *xsp_alloc_pass_user_info();
void xsp_free_pass_user_info(xspPassUserInfo *ui);

#endif
