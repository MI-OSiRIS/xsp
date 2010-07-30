#ifndef XSPD_LISTENER_H
#define XSPD_LISTENER_H

#include "xspd_conn.h"

enum listener_status { LISTENER_STOPPED, LISTENER_RUNNING };

typedef struct xspd_listener_t {
	char *id;
	char *name;
	enum listener_status status;

	const char *protocol;
	xspdSettings *settings;
	int one_shot;
	int (*callback) (struct xspd_listener_t *listener, struct xspd_connection_t *conn, void *arg);
	void *arg;

	void *proto_private;

	int (*start) (struct xspd_listener_t *listener);
	int (*stop) (struct xspd_listener_t *listener);
	void (*free) (struct xspd_listener_t *listener);

	int references;

	pthread_mutex_t lock;
} xspdListener;

typedef int (*listener_cb) (xspdListener *listener, struct xspd_connection_t *conn, void *arg);

xspdListener *xspd_listener_alloc();
xspdListener *xspd_listener_alloc_set(const char *listener_id, const char *protocol, xspdSettings *settings, int one_shot, listener_cb callback, void *arg);
void xspd_listener_free(xspdListener *listener);

int xspd_listener_start(xspdListener *listener);
int __xspd_listener_start(xspdListener *listener);
int xspd_listener_stop(xspdListener *listener);
int __xspd_listener_stop(xspdListener *listener);

xspdListener *xspd_listener_get_ref(xspdListener *listener);
void xspd_listener_put_ref(xspdListener *listener);

#endif
