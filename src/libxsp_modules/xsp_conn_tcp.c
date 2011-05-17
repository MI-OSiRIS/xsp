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
#include <sys/poll.h>

#include "xsp_conn_tcp.h"
#include "xsp_protocols.h"
#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_modules.h"

#include "splice.h"
#include "compat.h"

xspConn *xsp_conn_tcp_alloc(int sd, int use_web100);
static xspConn_tcpData *xsp_conn_tcp_data_alloc(int sd);
static int xsp_conn_tcp_splice(xspConn *src, xspConn *sink, size_t len, int flags);
static int xsp_conn_tcp_src_splice(xspConn *src, int fd, size_t len, int flags);
static int xsp_conn_tcp_sink_splice(xspConn *sink, int fd, size_t len, int flags);
static int xsp_conn_tcp_read(xspConn *src, void *buf, size_t len, int flags);
static int xsp_conn_tcp_write(xspConn *sink, const void *buf, size_t len, int flags);
static int xsp_conn_tcp_shutdown(xspConn *conn, uint8_t direction);
static int xsp_conn_tcp_setbufsize(xspConn *conn, uint8_t direction, int size);
static int xsp_conn_tcp_settimeout(xspConn *conn, uint8_t direction, int seconds);
static void xsp_conn_tcp_free_tcp_data(xspConn *conn);

#ifdef HAVE_WEB100
#include "xsp_web100.h"

static int xsp_conn_tcp_web100_read(xspConn *src, void *buf, size_t len, int flags);
static int xsp_conn_tcp_web100_write(xspConn *sink, const void *buf, size_t len, int flags);
void xsp_proto_tcp_try_convert_web100(xspConn *conn);
#endif

xspConn *xsp_conn_tcp_alloc(int sd, int use_web100) {
	xspConn *new_conn;
	struct sockaddr_storage sa;
	SOCKLEN_T sa_len = sizeof(struct sockaddr_storage);
	char buf[10];

	new_conn = xsp_conn_alloc();
	if (!new_conn)
		goto error_exit;

	new_conn->conn_private = xsp_conn_tcp_data_alloc(sd);
	if (!new_conn->conn_private) {
		xsp_err(10, "couldn't allocate tcp data structure");
		goto error_exit2;
	}

#ifdef HAVE_WEB100
	if (use_web100) {
		xsp_info(0, "using web100 statistics gathering");
		new_conn->stats_private = xsp_alloc_web100_stats(sd);
	} else {
		xsp_info(0, "using default statistics gathering");
		new_conn->stats_private = xsp_conn_stats_alloc_def();
	}
#else
	xsp_info(0, "using default statistics gathering");
	new_conn->stats_private = xsp_conn_stats_alloc_def();
#endif

	if (!new_conn->stats_private) {
		xsp_err(0, "couldn't allocate tcp stats structure");
		goto error_exit3;
	}

	new_conn->protocol = "TCP";
	new_conn->status = STATUS_CONNECTED;

	if (getpeername(sd, (struct sockaddr *) &sa, &sa_len) == 0) {
		new_conn->description = xsp_sa2hopid((struct sockaddr *) &sa, sizeof(sa), 0);
	}

	if (new_conn->description == NULL) {
		sprintf(buf, "%d", sd);
		new_conn->description = strdup(buf);
	}
	
	new_conn->splice2 = xsp_conn_tcp_splice;
	new_conn->src_splice2 = xsp_conn_tcp_src_splice;
	new_conn->sink_splice2 = xsp_conn_tcp_sink_splice;
	new_conn->read2 = xsp_conn_tcp_read;
	new_conn->write2 = xsp_conn_tcp_write;
	new_conn->shutdown2 = xsp_conn_tcp_shutdown;
	new_conn->setbufsize2 = xsp_conn_tcp_setbufsize;
	new_conn->settimeout2 = xsp_conn_tcp_settimeout;
	new_conn->free_conn_private2 = xsp_conn_tcp_free_tcp_data;
	new_conn->get_stat2 = xsp_conn_default_get_stat;
	new_conn->free_stats2 = xsp_conn_free_stats_def;
	new_conn->send_msg2 = xsp_conn_default_send_msg;
	new_conn->get_msg2 = xsp_conn_default_get_msg;
	new_conn->set_session_status2=xsp_conn_default_set_session_status;

#ifdef HAVE_WEB100
	if (use_web100) {
		new_conn->read2 = xsp_conn_tcp_web100_read;
		new_conn->write2 = xsp_conn_tcp_web100_write;
		new_conn->free_stats2 = xsp_web100_free_stats;
	}
#endif
	return new_conn;

error_exit3:
	free(new_conn->conn_private);
error_exit2:
	free(new_conn);
error_exit:
	return NULL;
}


xspConn_tcpData *xsp_conn_tcp_data_alloc(int sd) {
	xspConn_tcpData *new_tcp_data;

	new_tcp_data = (xspConn_tcpData *) malloc(sizeof(xspConn_tcpData));
	if (!new_tcp_data)
		goto error_exit;

	if (pthread_mutex_init(&new_tcp_data->lock, NULL) != 0)
		goto error_exit2;

	new_tcp_data->sd = sd;
	new_tcp_data->closed = 0;

	return new_tcp_data;

error_exit2:
	free(new_tcp_data);
error_exit:
	return NULL;
}

static xsp_conn_tcp_splice(xspConn *src, xspConn *sink, size_t len, int flags) {
	int n;
	xspConn_tcpData *tcp_src = (xspConn_tcpData *) src->conn_private;
	xspConn_tcpData *tcp_sink = (xspConn_tcpData *) sink->conn_private;

	printf("calling splice: %d, %d, %d", tcp_src->sd, tcp_sink->sd, len);
	n = ssplice(tcp_src->sd, NULL, tcp_sink->sd, NULL, len, flags);

	if (n > 0) {
		((xspConn_defStats *)src->stats_private)->bytes_read += n;
		((xspConn_defStats *)sink->stats_private)->bytes_written += n;
	}
	return n;
}

static int xsp_conn_tcp_src_splice(xspConn *src, int fd, size_t len, int flags) {
	int n;
	int ret;
	xspConn_tcpData *tcp_src = (xspConn_tcpData *) src->conn_private;

	n = ssplice(tcp_src->sd, NULL, fd, NULL, len, flags);

	if (n > 0)
		((xspConn_defStats *)src->stats_private)->bytes_read += n;

	return n;
}

static int xsp_conn_tcp_sink_splice(xspConn *sink, int fd, size_t len, int flags) {
        int n;
	xspConn_tcpData *tcp_sink = (xspConn_tcpData *) sink->conn_private;

	n = ssplice(fd, NULL, tcp_sink->sd, NULL, len, flags);

	if (n > 0)
                ((xspConn_defStats *)sink->stats_private)->bytes_written += n;

        return n;
}

static int xsp_conn_tcp_write(xspConn *sink, const void *buf, size_t len, int flags) {
	int n;
	xspConn_tcpData *tcp_data = (xspConn_tcpData *) sink->conn_private;

        n = send(tcp_data->sd, buf, len, flags);

	if (n > 0)
		((xspConn_defStats *)sink->stats_private)->bytes_written += n;

	return n;
}

static int xsp_conn_tcp_read(xspConn *src, void *buf, size_t len, int flags) {
	int n;
	xspConn_tcpData *tcp_data = (xspConn_tcpData *) src->conn_private;

	n = recv(tcp_data->sd, buf, len, flags);

	if (n > 0)
		((xspConn_defStats *) src->stats_private)->bytes_read += n;

	return n;
}

static int xsp_conn_tcp_shutdown(xspConn *conn, uint8_t direction) {
	xspConn_tcpData *tcp_data = (xspConn_tcpData *) conn->conn_private;

	pthread_mutex_lock(&(tcp_data->lock));
	{
		tcp_data->closed |= direction;
		if (tcp_data->closed == (XSP_SEND_SIDE | XSP_RECV_SIDE)) {
			gettimeofday(&(conn->end_time), NULL);
			conn->status = STATUS_UNCONNECTED;
		}
	}
	pthread_mutex_unlock(&(tcp_data->lock));

	if (direction == XSP_SEND_SIDE) {
		xsp_info(10, "shutdown send side to \"%s\": %d", conn->description, tcp_data->sd);
		shutdown(tcp_data->sd, SHUT_WR);
	} else if (direction == XSP_RECV_SIDE) {
		xsp_info(10, "shutdown recv side to \"%s\": %d", conn->description, tcp_data->sd);
		shutdown(tcp_data->sd, SHUT_RD);
	} else if (direction == (XSP_RECV_SIDE | XSP_SEND_SIDE)) {
		xsp_info(10, "closed connection to \"%s\": %d", conn->description, tcp_data->sd);
		close(tcp_data->sd);
	} else {
		return -1;
	}

	return 0;
}

static int xsp_conn_tcp_setbufsize(xspConn *conn, uint8_t direction, int size) {
	xspConn_tcpData *tcp_data = (xspConn_tcpData *) conn->conn_private;
	int new_bufsize;
	int n;
	SOCKLEN_T junk;

	if (direction & XSP_RECV_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_RCVBUF, (const void *)&size, sizeof(int))) < 0) {
			xsp_err(10, "set recv buf of \"%s\" failed", conn->description);
			goto error_exit;
		}

		n = getsockopt(tcp_data->sd, SOL_SOCKET, SO_RCVBUF, (char *)&new_bufsize, (SOCKLEN_T *) &junk);
		if (n == 0) {
			xsp_info(5, "set recv buf of \"%s\" to \"%d\"",
					conn->description,
					new_bufsize);
		}
	}

	if (direction & XSP_SEND_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_SNDBUF, (const void *)&size, sizeof(int))) < 0) {
			xsp_err(10, "set send buf of \"%s\" failed", conn->description);
			goto error_exit;
		}

		n = getsockopt(tcp_data->sd, SOL_SOCKET, SO_SNDBUF, (char *)&new_bufsize, (SOCKLEN_T *) &junk);
		if (n == 0) {
			xsp_info(5, "set send buf of \"%s\" to \"%d\"",
					conn->description,
					new_bufsize);
		}

	}
	
	return 0;

error_exit:
	return -1;
}

static int xsp_conn_tcp_settimeout(xspConn *conn, uint8_t direction, int seconds) {
	xspConn_tcpData *tcp_data = (xspConn_tcpData *) conn->conn_private;
	struct timeval new_to;

	new_to.tv_sec = seconds;
	new_to.tv_usec = 0;

	if (direction & XSP_RECV_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_RCVTIMEO, &new_to, sizeof(struct timeval))) < 0) {
			xsp_err(5, "failed to set recv timeout of \"%s\" to \"%d\"",
					conn->description,
					seconds);
			goto error_exit;
		}

	} 
	
	if (direction & XSP_SEND_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_SNDTIMEO, &new_to, sizeof(struct timeval))) < 0) {
			xsp_info(5, "failed to set send timeout of \"%s\" to \"%d\"",
					conn->description,
					seconds);
			goto error_exit;
		}

	}

	return 0;

error_exit:
	return -1;
}

static void xsp_conn_tcp_free_tcp_data(xspConn *conn) {
	free(conn->conn_private);
}


#ifdef HAVE_WEB100

static int xsp_conn_tcp_web100_write(xspConn *sink, const void *buf, size_t len, int flags) {
	return send(((xspConn_tcpData *) sink->conn_private)->sd, buf, len, flags);
}

static int xsp_conn_tcp_web100_read(xspConn *src, void *buf, size_t len, int flags) {
	return recv(((xspConn_tcpData *) src->conn_private)->sd, buf, len, flags);
}

#endif
