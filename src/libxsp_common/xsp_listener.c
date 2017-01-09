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
#include <stdlib.h>
#include <string.h>

#include "xsp_logger.h"
#include "xsp_listener.h"
#include "xsp_common.h"
#include "xsp_protocols.h"

#include "hashtable.h"

xspListener *xsp_listener_alloc() {
  xspListener *new_listener;

  new_listener = malloc(sizeof(xspListener));
  if (!new_listener)
    return NULL;

  bzero(new_listener, sizeof(*new_listener));

  return new_listener;
}

xspListener *xsp_listener_alloc_set(const char *listener_id, const char *protocol, xspSettings *settings, int one_shot, listener_cb callback, void *arg) {
  xspListener *new_listener;

  new_listener = xsp_protocol_setup_listener(listener_id, protocol, settings, one_shot, callback, arg);
  if (!new_listener) {
    xsp_err(0, "couldn't create listener");
    goto error_exit;
  }

  return new_listener;

error_exit:
  return NULL;
}

void xsp_listener_free(xspListener *listener) {
  if (listener->id)
    free(listener->id);
  if (listener->settings)
    xsp_settings_free(listener->settings);
  free(listener);
}

int xsp_listener_start(xspListener *listener) {
  int n;

  pthread_mutex_lock(&listener->lock);
  {
    n = listener->start(listener);
  }
  pthread_mutex_unlock(&listener->lock);

  return n;
}

int __xsp_listener_start(xspListener *listener) {
  return listener->start(listener);
}

int xsp_listener_stop(xspListener *listener) {
  int n;

  pthread_mutex_lock(&listener->lock);
  {
    n = listener->stop(listener);
  }
  pthread_mutex_unlock(&listener->lock);

  return n;
}

int __xsp_listener_stop(xspListener *listener) {
  return listener->stop(listener);
}

xspListener *xsp_listener_get_ref(xspListener *listener) {
  pthread_mutex_lock(&listener->lock);
  {
    xsp_info(5, "%s: got reference for session", listener->id);
    listener->references++;
  }
  pthread_mutex_unlock(&listener->lock);

  return listener;
}

void xsp_listener_put_ref(xspListener *listener) {

  pthread_mutex_lock(&listener->lock);

  xsp_info(5, "%s: put reference for listener", listener->id);
  listener->references--;

  if (listener->references == 0) {
    xsp_info(5, "%s: no more references for listener, cleaning up", listener->id);
    pthread_mutex_unlock(&listener->lock);
    xsp_listener_free(listener);
  }
  else {
    pthread_mutex_unlock(&listener->lock);
  }
}
