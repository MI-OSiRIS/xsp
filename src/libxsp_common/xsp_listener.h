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
#ifndef XSP_LISTENER_H
#define XSP_LISTENER_H

#include "xsp_conn.h"

enum listener_status { LISTENER_STOPPED, LISTENER_RUNNING };

typedef struct xsp_listener_t {
	char *id;
	char *name;
	enum listener_status status;

	const char *protocol;
	xspSettings *settings;
	int one_shot;
	int (*callback) (struct xsp_listener_t *listener, struct xsp_connection_t *conn, void *arg);
	void *arg;

	void *proto_private;

	int (*start) (struct xsp_listener_t *listener);
	int (*stop) (struct xsp_listener_t *listener);
	void (*free) (struct xsp_listener_t *listener);

	int references;

	pthread_mutex_t lock;
} xspListener;

typedef int (*listener_cb) (xspListener *listener, struct xsp_connection_t *conn, void *arg);

xspListener *xsp_listener_alloc();
xspListener *xsp_listener_alloc_set(const char *listener_id, const char *protocol, xspSettings *settings, int one_shot, listener_cb callback, void *arg);
void xsp_listener_free(xspListener *listener);

int xsp_listener_start(xspListener *listener);
int __xsp_listener_start(xspListener *listener);
int xsp_listener_stop(xspListener *listener);
int __xsp_listener_stop(xspListener *listener);

xspListener *xsp_listener_get_ref(xspListener *listener);
void xsp_listener_put_ref(xspListener *listener);

#endif
