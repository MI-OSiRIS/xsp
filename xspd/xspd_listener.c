#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "xspd_logger.h"
#include "xspd_listener.h"
#include "xspd_common.h"
#include "xspd_protocols.h"

#include "hashtable.h"

xspdListener *xspd_listener_alloc() {
	xspdListener *new_listener;

	new_listener = malloc(sizeof(xspdListener));
	if (!new_listener)
		return NULL;

	bzero(new_listener, sizeof(*new_listener));

	return new_listener;
}

xspdListener *xspd_listener_alloc_set(const char *listener_id, const char *protocol, xspdSettings *settings, int one_shot, listener_cb callback, void *arg) {
	xspdListener *new_listener;

	new_listener = xspd_protocol_setup_listener(listener_id, protocol, settings, one_shot, callback, arg);
	if (!new_listener) {
		xspd_err(0, "couldn't create listener");
		goto error_exit;
	}

	return new_listener;

error_exit:
	return NULL;
}

void xspd_listener_free(xspdListener *listener) {
	if (listener->id)
		free(listener->id);
	if (listener->settings)
		xspd_settings_free(listener->settings);
	free(listener);
}

int xspd_listener_start(xspdListener *listener) {
	int n;

	pthread_mutex_lock(&listener->lock);
	{
		n = listener->start(listener);
	}
	pthread_mutex_unlock(&listener->lock);

	return n;
}

int __xspd_listener_start(xspdListener *listener) {
	return listener->start(listener);
}

int xspd_listener_stop(xspdListener *listener) {
	int n;

	pthread_mutex_lock(&listener->lock);
	{
		n = listener->stop(listener);
	}
	pthread_mutex_unlock(&listener->lock);

	return n;
}

int __xspd_listener_stop(xspdListener *listener) {
	return listener->stop(listener);
}

xspdListener *xspd_listener_get_ref(xspdListener *listener) {
	pthread_mutex_lock(&listener->lock);
	{
		xspd_info(5, "%s: got reference for session", listener->id);
		listener->references++;
	}
	pthread_mutex_unlock(&listener->lock);

	return listener;
}

void xspd_listener_put_ref(xspdListener *listener) {

	pthread_mutex_lock(&listener->lock);

	xspd_info(5, "%s: put reference for listener", listener->id);
	listener->references--;

	if (listener->references == 0) {
		xspd_info(5, "%s: no more references for listener, cleaning up", listener->id);
		pthread_mutex_unlock(&listener->lock);
		xspd_listener_free(listener);
	} else {
		pthread_mutex_unlock(&listener->lock);
	}
}
