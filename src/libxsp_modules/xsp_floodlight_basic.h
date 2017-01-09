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
#ifndef XSP_FLOODLIGHT_BASIC_H
#define XSP_FLOODLIGHT_BASIC_H

#include <pthread.h>

typedef struct xsp_fl_config_t {
  char *controller_hp;
} xspFLConfig;

typedef struct xsp_fl_entry_list_t {
  void **entries;
  int n_entries;
} xspFLEntries;

#endif
