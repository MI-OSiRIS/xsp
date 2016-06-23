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
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "xsp_conn_tcp.h"
#include "xsp_protocols.h"
#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_settings.h"
#include "xsp_listener.h"

#ifdef HAVE_WEB100
#include "xsp_web100.h"
#endif

#include "compat.h"

struct tcp_listener_args {
	int *sockets;
	int num_sockets;
	pthread_t accept_thread;
};

int xsp_proto_tcp_init();
static xspConn *xsp_proto_tcp_connect(const char *hop_id, xspSettings *settings);
static xspListener *xsp_proto_tcp_setup_listener(const char *listener_id, xspSettings *settings, int one_shot, listener_cb callback, void *arg);
static int xsp_proto_tcp_start_listener(xspListener *listener);
static int xsp_proto_tcp_stop_listener(xspListener *listener);
static void xsp_proto_tcp_free_listener(xspListener *listener);
static void *xsp_tcp_accept_handler(void *v);

static xspProtocolHandler xsp_tcp_handler = {
	.connect = xsp_proto_tcp_connect,
	.setup_listener = xsp_proto_tcp_setup_listener,
	.name = "tcp"
};

static xspModule xsp_tcp_module = {
	.desc = "TCP Handler Module",
	.dependencies = "",
	.init = xsp_proto_tcp_init
};

static int web100_available;

xspModule *module_info() {
	return &xsp_tcp_module;
}

int tcp_def_use_ipv6 = 0;
int tcp_def_incoming_port = 5006;
int tcp_def_outgoing_port = 5006;
int tcp_def_incoming_recv_bufsize = 0;
int tcp_def_incoming_send_bufsize = 0;
int tcp_def_incoming_recv_timeout = 0;
int tcp_def_incoming_send_timeout = 0;
int tcp_def_outgoing_recv_bufsize = 0;
int tcp_def_outgoing_send_bufsize = 0;
int tcp_def_outgoing_recv_timeout = 0;
int tcp_def_outgoing_send_timeout = 0;
#ifdef HAVE_WEB100
int tcp_def_web100_enabled = 0;
#endif

int xsp_proto_tcp_init() {

#ifdef HAVE_WEB100
	if (xsp_web100_init() != 0) {
		xsp_warn(0, "warning: web100 initialization failed");
		web100_available = 0;
	} else {
		web100_available = 1;
	}
#endif

	if (xsp_add_protocol_handler(&xsp_tcp_handler)) {
		xsp_err(0, "couldn't add protocol handler");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

static xspConn *xsp_proto_tcp_connect(const char *hostname, xspSettings *settings) {
	struct addrinfo hints;
	struct addrinfo *hop_addrs, *nexthop;
	char *addr;
	char port_str[10];
	int port;
	int retval;
	xspConn *ret_conn;
	int connected;
	int new_sd = 0;
	int recv_bufsize;
	int send_bufsize;
	int recv_timeout;
	int send_timeout;
	int use_web100;
	int use_ipv6;
	char *bind_interface;
	struct hostent *he;
	struct sockaddr_storage sa;

	// grab the tcp settings from the given policy
	if (xsp_settings_get_int_2(settings, "tcp", "port", &port) != 0) {
		port = tcp_def_outgoing_port;
	}

	if (xsp_settings_get_int_2(settings, "tcp", "recv_bufsize", &recv_bufsize) != 0) {
		recv_bufsize = tcp_def_outgoing_recv_bufsize;
	}

	if (xsp_settings_get_int_2(settings, "tcp", "send_bufsize", &send_bufsize) != 0) {
		send_bufsize = tcp_def_outgoing_send_bufsize;
	}

	if (xsp_settings_get_int_2(settings, "tcp", "recv_timeout", &recv_timeout) != 0) {
		recv_timeout = tcp_def_incoming_recv_timeout;
	}

	if (xsp_settings_get_int_2(settings, "tcp", "send_timeout", &send_timeout) != 0) {
		send_timeout = tcp_def_incoming_send_timeout;
	}

#ifdef HAVE_WEB100
	if (xsp_settings_get_bool_2(settings, "tcp", "use_web100", &use_web100) != 0) {
		use_web100 = web100_available;
	} else if (use_web100 == 1 && web100_available == 0) {
		xsp_warn(0, "requested web100 for tcp connection to %s, but web100 support is currently unavailable", hostname);
		use_web100 = 0;
	}
#else
	use_web100 = 0;
#endif

	if (xsp_settings_get_bool_2(settings, "tcp", "use_ipv6", &use_ipv6) != 0) {
		use_ipv6 = tcp_def_use_ipv6;
	}

	if (xsp_settings_get_2(settings, "tcp", "interface", &bind_interface) != 0) {
		bind_interface = NULL;
	}

	xsp_info(1, "connecting to %s/%d", hostname, port);

	snprintf(port_str, 10, "%d", port);

	bzero(&hints, sizeof(struct addrinfo));

	if (use_ipv6) {
		hints.ai_family = AF_INET6;
	} else {
		hints.ai_family = AF_INET;
	}

	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags |= AI_PASSIVE;

	retval = getaddrinfo(hostname, port_str, &hints, &hop_addrs);
	if (retval != 0) {
		xsp_err(1, "lookup of \"%s\" failed", hostname);
		goto error_exit;
	}

	if (bind_interface != NULL) {
		he = gethostbyname((const char *) bind_interface);
		if (he != NULL) {
			bzero((void *)&sa, sizeof(struct sockaddr_storage));
			((struct sockaddr *)&sa)->sa_family = he->h_addrtype;
			if (he->h_addrtype == AF_INET) {
				memcpy (&(((struct sockaddr_in *) &sa)->sin_addr), he->h_addr_list[0], he->h_length);
				((struct sockaddr_in *) &sa)->sin_port = 0;
			} else {
				memcpy (&(((struct sockaddr_in6 *) &sa)->sin6_addr), he->h_addr_list[0], he->h_length);
				((struct sockaddr_in6 *) &sa)->sin6_port = 0;
			}
		} else {
			bind_interface = NULL;
		}
	}

	connected = 0;

	for(nexthop = hop_addrs; nexthop != NULL && !connected; nexthop = nexthop->ai_next) {
		new_sd = socket(nexthop->ai_family, nexthop->ai_socktype, nexthop->ai_protocol);
		if (new_sd < 0) {
			xsp_warn(10, "socket() failed");
			continue;
		}

		if (bind_interface != NULL) {
			bind(new_sd, (struct sockaddr *)&sa, sizeof(sa));
		}

		if (recv_bufsize > 0) {
			setsockopt(new_sd, SOL_SOCKET, SO_RCVBUF, (char *)&recv_bufsize, sizeof(int));
		}

		if (send_bufsize > 0) {
			setsockopt(new_sd, SOL_SOCKET, SO_SNDBUF, (char *)&send_bufsize, sizeof(int));
		}

		if (send_timeout > 0) {
			setsockopt(new_sd, SOL_SOCKET, SO_SNDTIMEO, (char *)&send_timeout, sizeof(int));
		}

		if (recv_timeout > 0) {
			setsockopt(new_sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&recv_timeout, sizeof(int));
		}

		if (connect(new_sd, nexthop->ai_addr, nexthop->ai_addrlen) != 0) {
			xsp_warn(5, "connect() failed");
			close(new_sd);
			continue;
		}
		addr = strdup(inet_ntoa(((struct sockaddr_in*)nexthop->ai_addr)->sin_addr));
		connected = 1;
	}

	freeaddrinfo(hop_addrs);

	if (!connected) {
		xsp_err(0, "couldn't connect to \"%s\"", hostname);
		goto error_exit;
	}

	ret_conn = xsp_conn_tcp_alloc(new_sd, use_web100);
	if (!ret_conn) {
		xsp_err(10, "couldn't allocate socket structure");
		goto error_exit_sd;
	}

	xsp_info(1, "connected to %s", hostname);

	ret_conn->addr = addr;
	return ret_conn;

error_exit_sd:
	close(new_sd);
error_exit:
	return NULL;
}

static xspListener *xsp_proto_tcp_setup_listener(const char *listener_id, xspSettings *settings, int one_shot, listener_cb callback, void *arg) {
	xspListener *new_listener;
	struct tcp_listener_args *tcp_args;
	
	new_listener = xsp_listener_alloc();
	if (!new_listener)
		goto error_exit;

	new_listener->id = strdup(listener_id);
	if (!new_listener->id)
		goto error_exit_listener;

	new_listener->settings = xsp_settings_duplicate(settings);
	if (!new_listener->settings)
		goto error_exit_listener;

	tcp_args = malloc(sizeof(struct tcp_listener_args));
	if (!tcp_args)
		goto error_exit_listener;

	new_listener->status = LISTENER_STOPPED;
	new_listener->callback = callback;
	new_listener->arg = arg;
	new_listener->protocol = "tcp";
	new_listener->proto_private = tcp_args;
	new_listener->start = xsp_proto_tcp_start_listener;
	new_listener->stop = xsp_proto_tcp_stop_listener;
	new_listener->free = xsp_proto_tcp_free_listener;

	return new_listener;

error_exit_listener:
	xsp_listener_free(new_listener);
error_exit:
	return NULL;
}

static int xsp_proto_tcp_start_listener(xspListener *listener) {
	struct addrinfo *ai;
	int xsp_tcp_family;
	int i;
	int use_ipv6;
	char **interfaces;
	int num_interfaces;
	int recv_bufsize;
	int send_bufsize;
	int port;
	int *sockets;
	int num_sockets;
	struct tcp_listener_args *tcp_args = listener->proto_private;

	if (listener->status != LISTENER_STOPPED)
		return -1;

	// grab the tcp settings from the given policy
	if (xsp_settings_get_int_2(listener->settings, "tcp", "port", &port) != 0) {
		port = tcp_def_incoming_port;
	}

	if (xsp_settings_get_int_2(listener->settings, "tcp", "recv_bufsize", &recv_bufsize) != 0) {
		recv_bufsize = tcp_def_incoming_recv_bufsize;
	}

	if (xsp_settings_get_int_2(listener->settings, "tcp", "send_bufsize", &send_bufsize) != 0) {
		send_bufsize = tcp_def_incoming_send_bufsize;
	}

	if (xsp_settings_get_list_2(listener->settings, "tcp", "interfaces", &interfaces, &num_interfaces) != 0) {
		interfaces = NULL;
	}

	if (xsp_settings_get_bool_2(listener->settings, "tcp", "use_ipv6", &use_ipv6) != 0) {
		use_ipv6 = tcp_def_use_ipv6;
	}

	if (interfaces != NULL) {
		sockets = listen_port_iface(interfaces, num_interfaces, IPPROTO_TCP, port, &num_sockets);
		if (!sockets) {
			xsp_err(0, "couldn't listen on port: %d", port);
			goto error_exit;
		}
	} else {
		if (use_ipv6) {
			xsp_tcp_family = AF_INET6;
		} else {
			xsp_tcp_family = AF_INET;
		}

		sockets = listen_port(IPPROTO_TCP, xsp_tcp_family, port, &num_sockets, &ai);
		if (!sockets) {
			xsp_err(0, "couldn't listen on port: %d", port);
			goto error_exit;
		}

		freeaddrinfo(ai);
	}

	xsp_info(0, "TCP: num sockets: %d %d", num_sockets, sockets[0]);
	for(i = 0; i < num_sockets; i++) {

		//XXX This is only working for a single socket!
		struct sockaddr_in sa;
		socklen_t sa_len = sizeof(struct sockaddr_in);
		if (getsockname(sockets[i], (struct sockaddr *) &sa, &sa_len) == 0) {
			listener->name = xsp_sa2hopid((struct sockaddr *) &sa, sizeof(sa), 0);
		}
		
		if (recv_bufsize > 0) {
			setsockopt(sockets[i], SOL_SOCKET, SO_RCVBUF, &(recv_bufsize), sizeof(int));
		}

		if (send_bufsize > 0) {
			setsockopt(sockets[i], SOL_SOCKET, SO_SNDBUF, &(send_bufsize), sizeof(int));
		}
	}

	tcp_args->sockets = sockets;
	tcp_args->num_sockets = num_sockets;

	if (pthread_create(&tcp_args->accept_thread, NULL, xsp_tcp_accept_handler, (void *) listener) != 0) {
		xsp_err(0, "couldn't execute socket handler thread: %s", strerror(errno));
		goto error_exit_sockets;
	}

	listener->status = LISTENER_RUNNING;

	xsp_info(0, "Started TCP listener: %s", listener->id);

	return 0;

error_exit_sockets:
	for(i = 0; i < num_sockets; i++)
		close(sockets[i]);
	free(sockets);
error_exit:
	return -1;
}

static int xsp_proto_tcp_stop_listener(xspListener *listener) {
	struct tcp_listener_args *tcp_args = listener->proto_private;
	int i, n;

	if (listener->status != LISTENER_RUNNING) {
		xsp_err(0, "tried to stop a stopped listener: %d", listener->status);
		return -1;
	}

	if ((n = pthread_cancel(tcp_args->accept_thread)) < 0){
		xsp_err(0, "pthread_cancel failed: %d, %s", n, strerror(errno));
		return -1;
	}

	if ((n = pthread_join(tcp_args->accept_thread, NULL)) < 0){
		xsp_err(0, "pthread_join failed: %d, %s", n, strerror(errno));
		return -1;
	}

	for(i = 0; i < tcp_args->num_sockets; i++)
		close(tcp_args->sockets[i]);
	free(tcp_args->sockets);

	listener->status = LISTENER_STOPPED;

	return 0;
}

static void xsp_proto_tcp_free_listener(xspListener *listener) {
	struct tcp_listener_args *tcp_args = listener->proto_private;

	if (listener->status != LISTENER_STOPPED)
		xsp_proto_tcp_stop_listener(listener);

	// once it is stopped, all the resources associated with the
	// listener(thread, sockets, etc) should be free, so we can just free
	// the struct
	free(tcp_args);	
}

static void *xsp_tcp_accept_handler(void *v) {
	xspConn *new_conn;
	fd_set socket_set;
	int n, i, high;
	int sd;
	int use_web100;
	int recv_timeout;
	int send_timeout;
	xspListener *listener;
	struct tcp_listener_args *tcp_args;
	int old_state;
	
	listener = v;
	tcp_args = listener->proto_private;
	
	pthread_detach(pthread_self());
	
#ifdef HAVE_WEB100
	if (xsp_settings_get_bool_2(listener->settings, "tcp", "use_web100", &use_web100) != 0) {
		use_web100 = web100_available;
	} else if (use_web100 == 1 && web100_available == 0) {
		xsp_warn(0, "requested web100 for tcp listener but web100 support is currently unavailable");
		use_web100 = 0;
	}
#else
	use_web100 = 0;
#endif
	
	if (xsp_settings_get_int_2(listener->settings, "tcp", "send_timeout", &send_timeout) != 0) {
		send_timeout = tcp_def_incoming_send_timeout;
	}
	
	if (xsp_settings_get_int_2(listener->settings, "tcp", "recv_timeout", &recv_timeout) != 0) {
		recv_timeout = tcp_def_incoming_recv_timeout;
	}
	
	while(1) {
		struct timeval tv;
		
		FD_ZERO(&socket_set);
		
		high = 0;
		
		for(i = 0; i < tcp_args->num_sockets; i++) {
			FD_SET(tcp_args->sockets[i], &socket_set);
			if (tcp_args->sockets[i] > high)
				high = tcp_args->sockets[i];
			//xsp_info(1, "Adding %d to socket queue", tcp_args->sockets[i]);
#ifndef __APPLE__
			fcntl(tcp_args->sockets[i], F_SETFL, O_NONBLOCK);
#endif
		}
		
		//xsp_info(1, "Going into select");
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		n = select(high + 1, &socket_set, NULL, NULL, &tv);
		//xsp_info(1, "Coming out of select");
		
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
		
		for(i = 0; i < tcp_args->num_sockets; i++) {
			struct sockaddr_storage sa;
			SOCKLEN_T sa_len = sizeof(struct sockaddr_storage);
			
			sd = accept(tcp_args->sockets[i], (struct sockaddr *) &sa, &sa_len);
			if (sd < 0) {
				if (FD_ISSET(tcp_args->sockets[i], &socket_set))
					xsp_err(1, "accept failed: %s", strerror(errno));
				continue;
			}

			//xsp_info(0,"xsp_conn_tcp_alloc is called");
			new_conn = xsp_conn_tcp_alloc(sd, use_web100);
			if (!new_conn) {
				xsp_err(1, "xsp_conn_alloc_socket() failed: %s", strerror(errno));
				close(sd);
				continue;
			}
			
			new_conn->id = strdup(new_conn->description);
			
			//xsp_info(0, "new incoming connection: %s", new_conn->description);
			
			if (recv_timeout > 0) {
				struct timeval new_to;
				new_to.tv_sec = recv_timeout;
				new_to.tv_usec = 0;
				
				if ((setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &new_to, sizeof(struct timeval))) < 0) {
					xsp_warn(1, "failed to set recv timeout of \"%s\" to \"%d\"",
						 new_conn->description,
						 recv_timeout);
				}
			}
			
			//xsp_info(0, "post recv timeout: %s", new_conn->description);
			
			if (send_timeout > 0) {
				struct timeval new_to;
				new_to.tv_sec = send_timeout;
				new_to.tv_usec = 0;
				
				if ((setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &new_to, sizeof(struct timeval))) < 0) {
					xsp_warn(1, "failed to set send timeout of \"%s\" to \"%d\"",
						 new_conn->description,
						 recv_timeout);
				}
			}
			
			//xsp_info(0, "post send timeout: %s", new_conn->description);
			
			new_conn->settings = xsp_settings_duplicate(listener->settings);
			
			//xsp_info(0, "post settings duplicate: %s", new_conn->description);
			
			n = listener->callback(listener, new_conn, listener->arg);
			if (n == 0 && listener->one_shot)
				goto out;
			
			//xsp_info(0, "post call-back: %s", new_conn->description);
		}
		
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old_state);
	}
	
 out:
	xsp_info(1, "Closing all sockets and exiting listener");
	
	for(i = 0; i < tcp_args->num_sockets; i++)
		close(tcp_args->sockets[i]);
	free(tcp_args->sockets);
	
	listener->status = LISTENER_STOPPED;
	
	return NULL;
}
