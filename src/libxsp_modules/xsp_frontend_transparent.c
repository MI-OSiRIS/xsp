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
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"

#include "xsp_auth.h"
#include "xsp_conn.h"
#include "xsp_config.h"
#include "xsp_logger.h"
#include "xsp_tpool.h"
#include "xsp_conn_tcp.h"
#include "xsp_protocols.h"
#include "xsp_modules.h"
#include "xsp_main_settings.h"

#ifdef HAVE_NETFILTER
#include <linux/netfilter_ipv4.h>
#else
#ifdef HAVE_PF
// put the relevant info here
#endif
#endif

#include "compat.h"

static int xsp_frontend_transparent_init();
static int xsp_frontend_connection_handler(xspListener *listener, xspConn *conn, void *arg);
static void *xsp_handle_transparent_conn(void *arg);

static xspModule xsp_transparent_module = {
  .desc = "Transparent XSP Handler Module",
  .dependencies = "tcp auth_anon",
  .init = xsp_frontend_transparent_init,
  .opt_handler = NULL
};

int xsp_transparent_port = 5008;
int xsp_transparent_send_bufsize = 0;
int xsp_transparent_recv_bufsize = 0;
int xsp_transparent_send_timeout = 0;
int xsp_transparent_recv_timeout = 0;

xspModule *module_info() {
  return &xsp_transparent_module;
}

int xsp_sess_add_hop(comSess *sess, xspHop *hop) {
  xspHop **new_list;
  int new_count;

  new_count = sess->child_count + 1;

  new_list = (xspHop **) realloc(sess->child, sizeof(xspHop *) * new_count);
  if (!new_list)
    return -1;

  sess->child = new_list;

  sess->child[sess->child_count] = hop;
  sess->child_count++;

  hop->session = (xspSess*)sess;

  return 0;
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
      xsp_info(0, "Transparent module disabled");
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
  xspCreds *credentials;
  int child_fd;
  char **error_msgs = NULL;

  sess = xsp_alloc_com_sess();
  if (!sess) {
    xsp_err(5, "xsp_alloc_sess() failed: %s", strerror(errno));
    goto error_exit;
  }

  xsp_session_get_ref(sess);

  // generate a random session id
  gen_rand_hex(sess->id, 2*XSP_SESSIONID_LEN+1);

  hop = xsp_alloc_hop();
  if (!hop) {
    xsp_err(5, "xsp_alloc_hop() failed: %s", strerror(errno));
    free(sess);
    goto error_exit2;
  }

  hop->session = (xspSess *) sess;

  tcp_data = new_conn->conn_private;
  child_fd = tcp_data->sd;

  xspMsg msg = {
    .version = XSP_v0,
    .type = XSP_MSG_AUTH_TYPE,
    .msg_body = "ANON"
  };

  if (xsp_authenticate_connection(new_conn, &msg, &credentials) != 0) {
    xsp_err(0, "Authentication failed.");
    goto error_exit;
  }

  // copy the original address in here:
  if (getsockopt(child_fd, IPPROTO_IP, SO_ORIGINAL_DST, &sa, &sa_size) != 0) {
    xsp_err(5, "Couldn't get the original destination");
    perror("getsockopt");
    goto error_exit3;
  }

  // if the above fails, we should do a default route lookup based on the source

  if (xsp_sa2hopid_r((struct sockaddr *) &sa, sizeof(sa), hop->hop_id, sizeof(hop->hop_id), 0) == NULL) {
    xsp_err(5, "Couldn't convert destination to hop id");
    goto error_exit3;
  }

  if (xsp_sess_add_hop(sess, hop) != 0) {
    xsp_err(5, "Error adding \"%s\" to session", hop->hop_id);
    goto error_exit3;
  }

  LIST_INSERT_HEAD(&sess->parent_conns, new_conn, sess_entries);

  sess->credentials = credentials;
  xsp_session_set_user(sess, strdup(credentials->get_user(credentials)));

  xsp_info(0, "new user: \"%s\"(%s) from \"%s\"",
           xsp_session_get_user(sess),
           credentials->get_email(credentials),
           credentials->get_institution(credentials));

  gettimeofday(&sess->start_time, NULL);

  // any XSP-service than uses this module will need to define
  // the opt_handler function pointer
  if (xsp_transparent_module.opt_handler == NULL) {
    xsp_err(0, "handler undefined, closing connection");
  }
  else {
    // handle the connection
    if (xsp_transparent_module.opt_handler(sess)) {
      xsp_err(5, "Error in handling the session connection");
      goto error_exit4;
    }
  }

  gettimeofday(&sess->end_time, NULL);

  // if we get here, IO has finished for this session
  xsp_info(5, "session finished: %s", xsp_session_get_id(sess));

  xsp_session_finalize(sess);

  xsp_session_put_ref(sess);

  return NULL;

error_exit4:
  // XXX: need to close ALL the sessions
  xsp_end_session(sess);
error_exit3:
error_exit2:
error_exit:
  xsp_conn_shutdown(new_conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
  return NULL;
}
