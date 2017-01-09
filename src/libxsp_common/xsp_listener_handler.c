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
#include <string.h>

#include "xsp_common.h"
#include "xsp_listener.h"
#include "xsp_logger.h"
#include "xsp_session.h"
#include "hashtable.h"

static struct hashtable *listener_table = NULL;
static pthread_mutex_t listener_table_lock = PTHREAD_MUTEX_INITIALIZER;

DEFINE_HASHTABLE_INSERT(listener_table_insert, char, xspListener);
DEFINE_HASHTABLE_SEARCH(listener_table_search, char, xspListener);
DEFINE_HASHTABLE_REMOVE(listener_table_remove, char, xspListener);

int xsp_listener_handler_init() {

  listener_table = create_hashtable(10, id_hash_fn, id_equal_fn);
  if (!listener_table) {
    xsp_err(0, "couldn't create listener hash table");
    goto error_exit;
  }

  return 0;

error_exit:
  return -1;
}

int xsp_listener_handler_register_listener(xspListener *listener) {
  pthread_mutex_lock(&listener_table_lock);
  {
    if (listener_table_search(listener_table, listener->id) != NULL) {
      xsp_err(0, "tried to reregister listener: %s", listener->id);
      goto error_exit;
    }

    if (listener_table_insert(listener_table, strdup(listener->id), listener) == 0) {
      xsp_err(0, "couldn't insert listener into listener table");
      goto error_exit;
    }

    // grab a reference to the listener
    xsp_listener_get_ref(listener);
  }
  pthread_mutex_unlock(&listener_table_lock);

  return 0;

error_exit:
  pthread_mutex_unlock(&listener_table_lock);

  return -1;
}

void xsp_listener_handler_unregister_listener(const char *listener_id) {
  xspListener *listener;

  pthread_mutex_lock(&listener_table_lock);
  {
    listener = listener_table_remove(listener_table, listener_id);
    if (!listener) {
      xsp_info(5, "tried to unregister non-existent listener: %s", listener_id);
      goto error_exit;
    }

    xsp_info(5, "unregistered listener %s", listener->id);
  }
  pthread_mutex_unlock(&listener_table_lock);

  xsp_listener_put_ref(listener);

  return;

error_exit:
  pthread_mutex_unlock(&listener_table_lock);
  return;
}

void __xsp_listener_handler_unregister_listener(const char *listener_id) {
  xspListener *listener;

  pthread_mutex_lock(&listener_table_lock);
  {
    listener = listener_table_remove(listener_table, listener_id);
    if (!listener) {
      xsp_info(5, "tried to unregister non-existent listener: %s", listener_id);
      goto error_exit;
    }

    xsp_info(5, "unregistered listener %s", listener->id);
  }
  pthread_mutex_unlock(&listener_table_lock);

  xsp_listener_put_ref(listener);

  return;

error_exit:
  pthread_mutex_unlock(&listener_table_lock);
  return;
}

int xsp_listener_handler_start_listener(const char *listener_id) {
  int retval;

  pthread_mutex_lock(&listener_table_lock);
  {
    xspListener *listener;

    listener = listener_table_search(listener_table, listener_id);
    if (listener == NULL) {
      xsp_err(0, "no listener of id %s", listener_id);
      goto error_exit;
    }

    retval = listener->start(listener);
  }
  pthread_mutex_unlock(&listener_table_lock);

  return retval;

error_exit:
  pthread_mutex_unlock(&listener_table_lock);
  return -1;
}

int xsp_listener_handler_stop_listener(const char *listener_id) {
  int retval;

  pthread_mutex_lock(&listener_table_lock);
  {
    xspListener *listener;

    listener = listener_table_search(listener_table, listener_id);
    if (listener == NULL) {
      xsp_err(0, "no listener of id %s", listener_id);
      goto error_exit;
    }

    retval = listener->stop(listener);
  }
  pthread_mutex_unlock(&listener_table_lock);

  return retval;

error_exit:
  pthread_mutex_unlock(&listener_table_lock);
  return -1;
}

int xsp_listener_handler_shutdown_listener(const char *listener_id) {
  pthread_mutex_lock(&listener_table_lock);
  {
    xspListener *listener;

    listener = listener_table_remove(listener_table, listener_id);
    if (listener == NULL) {
      xsp_err(0, "no listener of id %s", listener_id);
      goto error_exit;
    }

    xsp_listener_put_ref(listener);
  }
  pthread_mutex_unlock(&listener_table_lock);

  return 0;

error_exit:
  pthread_mutex_unlock(&listener_table_lock);
  return -1;
}

xspListener *xsp_listener_handler_lookup_listener(const char *listener_id) {
  xspListener *listener;

  pthread_mutex_lock(&listener_table_lock);
  {

    listener = listener_table_search(listener_table, listener_id);
    if (listener == NULL) {
      xsp_err(0, "no listener of id %s", listener_id);
    }
    else {
      // bump the reference count before we return.
      xsp_listener_get_ref(listener);
    }
  }
  pthread_mutex_unlock(&listener_table_lock);

  return listener;
}
