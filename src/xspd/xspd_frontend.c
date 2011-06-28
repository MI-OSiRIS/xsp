#include <stdlib.h>
#include <string.h>

#include "queue.h"

#include "xsp_tpool.h"
#include "xsp_listener.h"
#include "xsp_settings.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_protocols.h"
#include "xsp_config.h"
#include "xsp_session.h"
#include "compat.h"

#include "xspd_frontend.h"

static int xspd_frontend_connection_handler(xspListener *listener, xspConn *conn, void *arg);
void *xspd_default_handle_conn(void *sess);
void *xspd_handle_proto_cb(comSess *sess, xspMsg *msg);

int xspd_frontend_start() {
	char **protocols;
	int i, num_protocols;
	xspSettings *settings;

	protocols = xsp_get_protocol_list(&num_protocols);
	if (!protocols) {
		xsp_err(0, "No protocols loaded");
		return -1;
	}
	if (xsp_main_settings_get_section("listeners", &settings) != 0) {
		xsp_info(5, "No listeners sections found, going with defaults");
		settings = xsp_settings_alloc();
	}
	
	for (i = 0; i < num_protocols; i++) {
		xspListener *listener;
		int disabled = 0;

		if (xsp_settings_get_bool_2(settings, protocols[i], "disabled", &disabled) != 0) {
			xsp_info(8, "Did not find a 'disabled' element in section '%s'", protocols[i]);
			disabled = 0;
		} else {
			xsp_info(8, "Found 'disabled' in section '%s': %d", protocols[i], disabled);
		}
		
		xsp_info(0, "Setting up listener for %s", protocols[i]);
		
		if ((listener = xsp_protocol_setup_listener(protocols[i], protocols[i], settings, 0, xspd_frontend_connection_handler, NULL)) == NULL) {
			xsp_err(0, "Couldn't setup listener for protocol %s", protocols[i]);
			return -1;
		}
		if (xsp_listener_start(listener) != 0) {
			xsp_err(0, "Couldn't start listener for protocol %s", protocols[i]);
			return -1;
		}
	}

	strlist_free(protocols, num_protocols);
	xsp_settings_free(settings);
	return 0;
}

static int xspd_frontend_connection_handler(xspListener *listener, xspConn *conn, void *arg) {
	int retval;
    
	xsp_info(0, "spawning default_handle_conn for %s", conn->description);

	retval = xsp_tpool_exec(xspd_default_handle_conn, conn);
	
	xsp_info(0, "done spawning default_handle_conn for %s", conn->description);

	return retval;
}

void *xspd_default_handle_conn(void *arg) {
	xspConn *conn = (xspConn *) arg;
	comSess *sess;

	xsp_wait_for_session(conn, &sess, NULL);
	
	if (!sess) {
		xsp_info(0, "could not get session");
		goto error_exit;
	}

	xsp_set_proto_cb(sess, xspd_handle_proto_cb);
	
	xsp_proto_loop(sess);

	return NULL;
 error_exit:
	return NULL;
	
}

void *xspd_handle_proto_cb(comSess *sess, xspMsg *msg) {

	xsp_info(0, "in proto cb");
	return NULL;
}
