#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"

#include "xspd_conn.h"
#include "xspd_session.h"
#include "xspd_config.h"
#include "xspd_logger.h"
#include "xspd_tpool.h"
#include "xspd_conn_tcp.h"
#include "xspd_protocols.h"
#include "xspd_modules.h"

#ifdef HAVE_NETFILTER
#include <linux/netfilter_ipv4.h>
#else
#ifdef HAVE_PF
// put the relevant info here...
#endif
#endif

#include "compat.h"

static int xspd_frontend_transparent_init();
static int xspd_frontend_connection_handler(xspdListener *listener, xspdConn *conn, void *arg);
static void *xspd_handle_transparent_conn(void *arg);

static xspdModule xspd_transparent_module = {
	.desc = "Transparent XSPD Handler Module",
	.dependencies = "tcp",
	.init = xspd_frontend_transparent_init
};

int xspd_transparent_port = 5008;
int xspd_transparent_send_bufsize = 0;
int xspd_transparent_recv_bufsize = 0;
int xspd_transparent_send_timeout = 0;
int xspd_transparent_recv_timeout = 0;

xspdModule *module_info() {
	return &xspd_transparent_module;
}

int xspd_frontend_transparent_init() {
	xspdSettings *settings;
	xspdListener *listener;
	int val;

	settings = xspd_settings_alloc();
	if (!settings) {
		xspd_err(0, "Couldn't allocate listener settings");
		goto error_exit;
	}

	if (xspd_main_settings_get_bool("transparent", "disabled", &val) == 0) {
		if (val) {
			xspd_info(0, "Transparent module disbaled");
			return 0;
		}
	}

	if (xspd_main_settings_get_int("transparent", "port", &val) == 0) {
		xspd_settings_set_int_2(settings, "tcp", "port", val);
	}

	if (xspd_main_settings_get_int("transparent", "send_bufsize", &val) == 0) {
		xspd_settings_set_int_2(settings, "tcp", "send_bufsize", val);
	}

	if (xspd_main_settings_get_int("transparent", "recv_bufsize", &val) == 0) {
		xspd_settings_set_int_2(settings, "tcp", "recv_bufsize", val);
	}

	if (xspd_main_settings_get_int("transparent", "send_timeout", &val) == 0) {
		xspd_settings_set_int_2(settings, "tcp", "send_timeout", val);
	}

	if (xspd_main_settings_get_int("transparent", "recv_timeout", &val) == 0) {
		xspd_settings_set_int_2(settings, "tcp", "recv_timeout", val);
	}

	xspd_info(0, "Setting up listener for transparent XSPD module");

	if ((listener = xspd_protocol_setup_listener("transparent", "tcp", settings, 0, xspd_frontend_connection_handler, NULL)) == NULL) {
		xspd_err(0, "Couldn't setup listener for transparent XSPD module");
		goto error_exit_settings;
	}

	if (xspd_listener_start(listener) != 0) {
		xspd_err(0, "Couldn't start listener for transparent XSPD module");
		goto error_exit_listener;
	}

	return 0;

error_exit_listener:
	xspd_listener_free(listener);
error_exit_settings:
	xspd_settings_free(settings);
error_exit:
	return -1;
}

static int xspd_frontend_connection_handler(xspdListener *listener, xspdConn *conn, void *arg) {
	int retval;

	retval = xspd_tpool_exec(xspd_handle_transparent_conn, conn);

	return retval;
}

void *xspd_handle_transparent_conn(void *arg) {
	xspdConn *new_conn = (xspdConn *) arg;
	xspdSess *sess;
	xspHop *hop;
	struct sockaddr_storage sa;
	SOCKLEN_T sa_size = sizeof(struct sockaddr_storage);
	xspdConn_tcpData *tcp_data;
	int child_fd;
	char **error_msgs = NULL;

	sess = xspd_alloc_sess();
	if (!sess) {
		xspd_err(5, "xspd_alloc_sess() failed: %s", strerror(errno));
		goto error_exit;
	}

	xspd_session_get_ref(sess);

	// generate a random session id
	gen_rand_hex(sess->id, sizeof(sess->id));

	hop = xsp_alloc_hop();
	if (!hop) {
		xspd_err(5, "xsp_alloc_hop() failed: %s", strerror(errno));
		goto error_exit2;
	}

	hop->session = (xspSess *) sess;

	tcp_data = new_conn->conn_private;
	child_fd = tcp_data->sd;

#ifdef HAVE_NETFILTER
	// copy the original address in here:
	if (getsockopt(child_fd, SOL_IP, SO_ORIGINAL_DST, &sa, &sa_size) != 0) {
		xspd_err(5, "Couldn't get the original destination"); 
		goto error_exit3;
	}
#else
	xspd_err(5, "No Netfilter support");
	goto error_exit3;
#endif

	if (xsp_sa2hopid_r((struct sockaddr *) &sa, sizeof(sa), hop->hop_id, sizeof(hop->hop_id), 0) == NULL) {
		xspd_err(5, "Couldn't convert destination to hop id");
		goto error_exit3;
	}

	if (xsp_sess_addhop((xspSess *) sess, hop) != 0) {
		xspd_err(5, "Error adding \"%s\" to session", hop->hop_id);
		goto error_exit3;
	}

	LIST_INSERT_HEAD(&sess->parent_conns, new_conn, sess_entries);
	xspd_session_set_user(sess, NULL);

	gettimeofday(&sess->start_time, NULL);

	if (xspd_setup_session(sess, &error_msgs) < 0) {
		xspd_err(5, "Couldn't setup sessions");
		goto error_exit4;
	}

	if (LIST_EMPTY(&sess->child_conns)) {
		xspd_err(5, "No one to send to");
		goto error_exit4;
	}

	// XXX: we're going to need something more complex for transparent sessions... sigh
	if (xspd_session_main_loop(sess)) {
		xspd_err(5, "Error in session main loop");
		goto error_exit4;
	}

	gettimeofday(&sess->end_time, NULL);

	// if we get here, IO has finished for this session
	xspd_info(5, "session finished: %s", xspd_session_get_id(sess));

	xspd_session_finalize(sess);

	xspd_session_put_ref(sess);

	return NULL;

error_exit4:
	// XXX: need to close ALL the sessions
error_exit3:
	free(hop);
error_exit2:
	free(sess);
error_exit:
	xspd_conn_shutdown(new_conn, (XSPD_SEND_SIDE | XSPD_RECV_SIDE));
	return NULL;
}
