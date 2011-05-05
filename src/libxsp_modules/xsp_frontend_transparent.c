#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"

#include "xsp_conn.h"
#include "xsp_session.h"
#include "xsp_config.h"
#include "xsp_logger.h"
#include "xsp_tpool.h"
#include "xsp_conn_tcp.h"
#include "xsp_protocols.h"
#include "xsp_modules.h"

#ifdef HAVE_NETFILTER
#include <linux/netfilter_ipv4.h>
#else
#ifdef HAVE_PF
// put the relevant info here...
#endif
#endif

#include "compat.h"

static int xsp_frontend_transparent_init();
static int xsp_frontend_connection_handler(xspListener *listener, xspConn *conn, void *arg);
static void *xsp_handle_transparent_conn(void *arg);

static xspModule xsp_transparent_module = {
	.desc = "Transparent XSP Handler Module",
	.dependencies = "tcp",
	.init = xsp_frontend_transparent_init
};

int xsp_transparent_port = 5008;
int xsp_transparent_send_bufsize = 0;
int xsp_transparent_recv_bufsize = 0;
int xsp_transparent_send_timeout = 0;
int xsp_transparent_recv_timeout = 0;

xspModule *module_info() {
	return &xsp_transparent_module;
}

int xsp_frontend_transparent_init() {
	xspSettings *settings;
	xspListener *listener;
	int val;

	settings = xsp_settings_alloc();
	if (!settings) {
		xsp_err(0, "Couldn't allocate listener settings");
		goto error_exit;
	}

	if (xsp_main_settings_get_bool("transparent", "disabled", &val) == 0) {
		if (val) {
			xsp_info(0, "Transparent module disbaled");
			return 0;
		}
	}

	if (xsp_main_settings_get_int("transparent", "port", &val) == 0) {
		xsp_settings_set_int_2(settings, "tcp", "port", val);
	}

	if (xsp_main_settings_get_int("transparent", "send_bufsize", &val) == 0) {
		xsp_settings_set_int_2(settings, "tcp", "send_bufsize", val);
	}

	if (xsp_main_settings_get_int("transparent", "recv_bufsize", &val) == 0) {
		xsp_settings_set_int_2(settings, "tcp", "recv_bufsize", val);
	}

	if (xsp_main_settings_get_int("transparent", "send_timeout", &val) == 0) {
		xsp_settings_set_int_2(settings, "tcp", "send_timeout", val);
	}

	if (xsp_main_settings_get_int("transparent", "recv_timeout", &val) == 0) {
		xsp_settings_set_int_2(settings, "tcp", "recv_timeout", val);
	}

	xsp_info(0, "Setting up listener for transparent XSP module");

	if ((listener = xsp_protocol_setup_listener("transparent", "tcp", settings, 0, xsp_frontend_connection_handler, NULL)) == NULL) {
		xsp_err(0, "Couldn't setup listener for transparent XSP module");
		goto error_exit_settings;
	}

	if (xsp_listener_start(listener) != 0) {
		xsp_err(0, "Couldn't start listener for transparent XSP module");
		goto error_exit_listener;
	}

	return 0;

error_exit_listener:
	xsp_listener_free(listener);
error_exit_settings:
	xsp_settings_free(settings);
error_exit:
	return -1;
}

static int xsp_frontend_connection_handler(xspListener *listener, xspConn *conn, void *arg) {
	int retval;

	retval = xsp_tpool_exec(xsp_handle_transparent_conn, conn);

	return retval;
}

void *xsp_handle_transparent_conn(void *arg) {
	xspConn *new_conn = (xspConn *) arg;
	comSess *sess;
	xspHop *hop;
	struct sockaddr_storage sa;
	SOCKLEN_T sa_size = sizeof(struct sockaddr_storage);
	xspConn_tcpData *tcp_data;
	int child_fd;
	char **error_msgs = NULL;

	sess = xsp_alloc_sess();
	if (!sess) {
		xsp_err(5, "xsp_alloc_sess() failed: %s", strerror(errno));
		goto error_exit;
	}

	xsp_session_get_ref(sess);

	// generate a random session id
	gen_rand_hex(sess->id, sizeof(sess->id));

	hop = xsp_alloc_hop();
	if (!hop) {
		xsp_err(5, "xsp_alloc_hop() failed: %s", strerror(errno));
		goto error_exit2;
	}

	hop->session = (comSess *) sess;

	tcp_data = new_conn->conn_private;
	child_fd = tcp_data->sd;

#ifdef HAVE_NETFILTER
	// copy the original address in here:
	if (getsockopt(child_fd, SOL_IP, SO_ORIGINAL_DST, &sa, &sa_size) != 0) {
		xsp_err(5, "Couldn't get the original destination"); 
		goto error_exit3;
	}
#else
	xsp_err(5, "No Netfilter support");
	goto error_exit3;
#endif

	if (xsp_sa2hopid_r((struct sockaddr *) &sa, sizeof(sa), hop->hop_id, sizeof(hop->hop_id), 0) == NULL) {
		xsp_err(5, "Couldn't convert destination to hop id");
		goto error_exit3;
	}

	if (xsp_sess_addhop((comSess *) sess, hop) != 0) {
		xsp_err(5, "Error adding \"%s\" to session", hop->hop_id);
		goto error_exit3;
	}

	LIST_INSERT_HEAD(&sess->parent_conns, new_conn, sess_entries);
	xsp_session_set_user(sess, NULL);

	gettimeofday(&sess->start_time, NULL);

	if (xsp_setup_session(sess, &error_msgs) < 0) {
		xsp_err(5, "Couldn't setup sessions");
		goto error_exit4;
	}

	if (LIST_EMPTY(&sess->child_conns)) {
		xsp_err(5, "No one to send to");
		goto error_exit4;
	}

	// XXX: we're going to need something more complex for transparent sessions... sigh
	if (xsp_session_main_loop(sess)) {
		xsp_err(5, "Error in session main loop");
		goto error_exit4;
	}

	gettimeofday(&sess->end_time, NULL);

	// if we get here, IO has finished for this session
	xsp_info(5, "session finished: %s", xsp_session_get_id(sess));

	xsp_session_finalize(sess);

	xsp_session_put_ref(sess);

	return NULL;

error_exit4:
	// XXX: need to close ALL the sessions
error_exit3:
	free(hop);
error_exit2:
	free(sess);
error_exit:
	xsp_conn_shutdown(new_conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
	return NULL;
}
