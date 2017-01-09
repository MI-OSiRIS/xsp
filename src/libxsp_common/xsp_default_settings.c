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
#include <pthread.h>
#include <string.h>

#include "xsp_settings.h"
#include "xsp_default_settings.h"
#include "xsp_logger.h"

static xspSettings *incoming_default_settings = NULL;
static xspSettings *outgoing_default_settings = NULL;
static xspSettings *both_default_settings = NULL;
static pthread_mutex_t default_settings_lock;

int xsp_default_settings_init() {

  if (pthread_mutex_init(&default_settings_lock, 0) != 0) {
    xsp_err(0, "couldn't initialize the default settings lock");
    goto error_exit;
  }

  return 0;

error_exit:
  return -1;
}

xspSettings *xsp_default_settings(enum xsp_direction_t direction) {
  xspSettings *ret_settings;

  pthread_mutex_lock(&default_settings_lock);
  {
    switch (direction) {
    case XSP_INCOMING:
      ret_settings = incoming_default_settings;
      break;
    case XSP_OUTGOING:
      ret_settings = outgoing_default_settings;
      break;
    case XSP_BOTH:
      ret_settings = both_default_settings;
      break;
    default:
      ret_settings = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&default_settings_lock);

  return ret_settings;
}

int xsp_set_default_settings(xspSettings *settings, enum xsp_direction_t direction) {
  int retval;

  pthread_mutex_lock(&default_settings_lock);
  {
    switch (direction) {
    case XSP_INCOMING:
      incoming_default_settings = settings;
      retval = 0;
      break;
    case XSP_OUTGOING:
      outgoing_default_settings = settings;
      retval = 0;
      break;
    case XSP_BOTH:
      both_default_settings = settings;
      retval = 0;
      break;
    default:
      retval = -1;
      break;
    }
  }
  pthread_mutex_unlock(&default_settings_lock);

  return retval;
}
