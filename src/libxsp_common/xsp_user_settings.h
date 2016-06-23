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
#ifndef XSP_USER_POLICY_H
#define XSP_USER_POLICY_H

#include "xsp_settings.h"
#include "xsp_common.h"

int xsp_user_settings_init();
xspSettings *xsp_user_settings(const char *user, enum xsp_direction_t direction);
int xsp_set_user_settings(char *user, enum xsp_direction_t direction, xspSettings *settings);

#endif
