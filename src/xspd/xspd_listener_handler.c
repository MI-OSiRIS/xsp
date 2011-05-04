#include <string.h>

#include "xspd_common.h"
#include "xspd_listener.h"
#include "xspd_logger.h"
#include "xspd_session.h"
#include "hashtable.h"

static struct hashtable *listener_table = NULL;
static pthread_mutex_t listener_table_lock = PTHREAD_MUTEX_INITIALIZER;

DEFINE_HASHTABLE_INSERT(listener_table_insert, char, xspdListener);
DEFINE_HASHTABLE_SEARCH(listener_table_search, char, xspdListener);
DEFINE_HASHTABLE_REMOVE(listener_table_remove, char, xspdListener);

int xspd_listener_handler_init() {

	listener_table = create_hashtable(10, id_hash_fn, id_equal_fn);
	if (!listener_table) {
		xspd_err(0, "couldn't create listener hash table");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

int xspd_listener_handler_register_listener(xspdListener *listener) {
	pthread_mutex_lock(&listener_table_lock);
	{
		if (listener_table_search(listener_table, listener->id) != NULL) {
			xspd_err(0, "tried to reregister listener: %s", listener->id);
			goto error_exit;
		}

		if (listener_table_insert(listener_table, strdup(listener->id), listener) == 0) {
			xspd_err(0, "couldn't insert listener into listener table");
			goto error_exit;
		}

		// grab a reference to the listener
		xspd_listener_get_ref(listener);
	}
	pthread_mutex_unlock(&listener_table_lock);

	return 0;

error_exit:
	pthread_mutex_unlock(&listener_table_lock);

	return -1;
}

void xspd_listener_handler_unregister_listener(const char *listener_id) {
	xspdListener *listener;

	pthread_mutex_lock(&listener_table_lock);
	{
		listener = listener_table_remove(listener_table, listener_id);
		if (!listener) {
			xspd_info(5, "tried to unregister non-existent listener: %s", listener_id);
			goto error_exit;
		}

		xspd_info(5, "unregistered listener %s", listener->id);
	}
	pthread_mutex_unlock(&listener_table_lock);

	xspd_listener_put_ref(listener);

	return;

error_exit:
	pthread_mutex_unlock(&listener_table_lock);
	return;
}

void __xspd_listener_handler_unregister_listener(const char *listener_id) {
	xspdListener *listener;

	pthread_mutex_lock(&listener_table_lock);
	{
		listener = listener_table_remove(listener_table, listener_id);
		if (!listener) {
			xspd_info(5, "tried to unregister non-existent listener: %s", listener_id);
			goto error_exit;
		}

		xspd_info(5, "unregistered listener %s", listener->id);
	}
	pthread_mutex_unlock(&listener_table_lock);

	xspd_listener_put_ref(listener);

	return;

error_exit:
	pthread_mutex_unlock(&listener_table_lock);
	return;
}

int xspd_listener_handler_start_listener(const char *listener_id) {
	int retval;

	pthread_mutex_lock(&listener_table_lock);
	{
		xspdListener *listener;

		listener = listener_table_search(listener_table, listener_id);
		if (listener == NULL) {
			xspd_err(0, "no listener of id %s", listener_id);
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

int xspd_listener_handler_stop_listener(const char *listener_id) {
	int retval;

	pthread_mutex_lock(&listener_table_lock);
	{
		xspdListener *listener;

		listener = listener_table_search(listener_table, listener_id);
		if (listener == NULL) {
			xspd_err(0, "no listener of id %s", listener_id);
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

int xspd_listener_handler_shutdown_listener(const char *listener_id) {
	pthread_mutex_lock(&listener_table_lock);
	{
		xspdListener *listener;

		listener = listener_table_remove(listener_table, listener_id);
		if (listener == NULL) {
			xspd_err(0, "no listener of id %s", listener_id);
			goto error_exit;
		}
	
		xspd_listener_put_ref(listener);	
	}
	pthread_mutex_unlock(&listener_table_lock);

	return 0;

error_exit:
	pthread_mutex_unlock(&listener_table_lock);
	return -1;
}

xspdListener *xspd_listener_handler_lookup_listener(const char *listener_id) {
	xspdListener *listener;

	pthread_mutex_lock(&listener_table_lock);
	{

		listener = listener_table_search(listener_table, listener_id);
		if (listener == NULL) {
			xspd_err(0, "no listener of id %s", listener_id);
		} else {
			// bump the reference count before we return.
			xspd_listener_get_ref(listener);
		}
	}
	pthread_mutex_unlock(&listener_table_lock);

	return listener;
}
