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
#ifndef XSP_OESS_BASIC_H
#define XSP_OESS_BASIC_H

#include <pthread.h>

enum {
  OESS_DATA = 0,
  OESS_MEASUREMENT,
  OESS_MONITORING,
  OESS_PROVISIONING,
  OESS_REMOTE,
};

typedef struct xsp_oess_config_t {
  char *service_ap;
  char *login;
  char *password;
  char *realm;
  char *project;
  void *auth_handler;
} xspOESSConfig;

#endif
