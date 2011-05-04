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

#include "xspd_conn_tcp.h"
#include "xspd_protocols.h"
#include "xspd_logger.h"
#include "xspd_config.h"
#include "xspd_tpool.h"
#include "xspd_modules.h"

#include "compat.h"

xspdConn *xspd_conn_tcp_alloc(int sd, int use_web100);
static xspdConn_tcpData *xspd_conn_tcp_data_alloc(int sd);
static int xspd_conn_tcp_splice(xspdConn *src, xspdConn *sink, size_t len, int flags);
static int xspd_conn_tcp_src_splice(xspdConn *src, int fd, size_t len, int flags);
static int xspd_conn_tcp_sink_splice(xspdConn *sink, int fd, size_t len, int flags);
static int xspd_conn_tcp_read(xspdConn *src, void *buf, size_t len, int flags);
static int xspd_conn_tcp_write(xspdConn *sink, const void *buf, size_t len, int flags);
static int xspd_conn_tcp_shutdown(xspdConn *conn, uint8_t direction);
static int xspd_conn_tcp_setbufsize(xspdConn *conn, uint8_t direction, int size);
static int xspd_conn_tcp_settimeout(xspdConn *conn, uint8_t direction, int seconds);
static void xspd_conn_tcp_free_tcp_data(xspdConn *conn);

#ifdef HAVE_WEB100
#include "xspd_web100.h"

static int xspd_conn_tcp_web100_read(xspdConn *src, void *buf, size_t len, int flags);
static int xspd_conn_tcp_web100_write(xspdConn *sink, const void *buf, size_t len, int flags);
void xspd_proto_tcp_try_convert_web100(xspdConn *conn);
#endif

xspdConn *xspd_conn_tcp_alloc(int sd, int use_web100) {
	xspdConn *new_conn;
	struct sockaddr_storage sa;
	SOCKLEN_T sa_len = sizeof(struct sockaddr_storage);
	char buf[10];

	new_conn = xspd_conn_alloc();
	if (!new_conn)
		goto error_exit;

	new_conn->conn_private = xspd_conn_tcp_data_alloc(sd);
	if (!new_conn->conn_private) {
		xspd_err(10, "couldn't allocate tcp data structure");
		goto error_exit2;
	}

#ifdef HAVE_WEB100
	if (use_web100) {
		xspd_info(0, "using web100 statistics gathering");
		//new_conn->stats_private = xspd_alloc_web100_stats(sd);
	} else {
		xspd_info(0, "using default statistics gathering");
		//new_conn->stats_private = xspd_conn_stats_alloc_def();
	}
#else
	xspd_info(0, "using default statistics gathering");
	//new_conn->stats_private = xspd_conn_stats_alloc_def();
#endif
	/*
	if (!new_conn->stats_private) {
		xspd_err(0, "couldn't allocate tcp stats structure");
		goto error_exit3;
	}
	*/
	new_conn->protocol = "TCP";
	new_conn->status = STATUS_CONNECTED;

	if (getpeername(sd, (struct sockaddr *) &sa, &sa_len) == 0) {
		new_conn->description = xsp_sa2hopid((struct sockaddr *) &sa, sizeof(sa), 0);
	}

	if (new_conn->description == NULL) {
		sprintf(buf, "%d", sd);
		new_conn->description = strdup(buf);
	}
	
	new_conn->splice2 = xspd_conn_tcp_splice;
	new_conn->src_splice2 = xspd_conn_tcp_src_splice;
	new_conn->sink_splice2 = xspd_conn_tcp_sink_splice;
	new_conn->read2 = xspd_conn_tcp_read;
	new_conn->write2 = xspd_conn_tcp_write;
	new_conn->shutdown2 = xspd_conn_tcp_shutdown;
	new_conn->setbufsize2 = xspd_conn_tcp_setbufsize;
	new_conn->settimeout2 = xspd_conn_tcp_settimeout;
	new_conn->free_conn_private2 = xspd_conn_tcp_free_tcp_data;
	//new_conn->get_stat2 = xspd_conn_default_get_stat;
	//new_conn->free_stats2 = xspd_conn_free_stats_def;
	new_conn->send_msg2 = xspd_conn_default_send_msg;
	new_conn->get_msg2 = xspd_conn_default_get_msg;

#ifdef HAVE_WEB100
	if (use_web100) {
		new_conn->read2 = xspd_conn_tcp_web100_read;
		new_conn->write2 = xspd_conn_tcp_web100_write;
		//new_conn->free_stats2 = xspd_web100_free_stats;
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


xspdConn_tcpData *xspd_conn_tcp_data_alloc(int sd) {
	xspdConn_tcpData *new_tcp_data;

	new_tcp_data = (xspdConn_tcpData *) malloc(sizeof(xspdConn_tcpData));
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

static xspd_conn_tcp_splice(xspdConn *src, xspdConn *sink, size_t len, int flags) {
	int n;
	xspdConn_tcpData *tcp_src = (xspdConn_tcpData *) src->conn_private;
	xspdConn_tcpData *tcp_sink = (xspdConn_tcpData *) sink->conn_private;

	printf("calling splice: %d, %d, %d", tcp_src->sd, tcp_sink->sd, len);
	n = ssplice(tcp_src->sd, NULL, tcp_sink->sd, NULL, len, flags);/*
	if (n > 0) {
		((xspdConn_defStats *)src->stats_private)->bytes_read += n;
		((xspdConn_defStats *)sink->stats_private)->bytes_written += n;
		}*/
	return n;
}

static int xspd_conn_tcp_src_splice(xspdConn *src, int fd, size_t len, int flags) {
	int n;
	int ret;
	xspdConn_tcpData *tcp_src = (xspdConn_tcpData *) src->conn_private;

	n = ssplice(tcp_src->sd, NULL, fd, NULL, len, flags);
	/*
	if (n > 0)
		((xspdConn_defStats *)src->stats_private)->bytes_read += n;
	*/
	return n;
}

static int xspd_conn_tcp_sink_splice(xspdConn *sink, int fd, size_t len, int flags) {
        int n;
	xspdConn_tcpData *tcp_sink = (xspdConn_tcpData *) sink->conn_private;

	n = ssplice(fd, NULL, tcp_sink->sd, NULL, len, flags);
	/*
	if (n > 0)
                ((xspdConn_defStats *)sink->stats_private)->bytes_written += n;
	*/
        return n;
}

static int xspd_conn_tcp_write(xspdConn *sink, const void *buf, size_t len, int flags) {
	int n;
	xspdConn_tcpData *tcp_data = (xspdConn_tcpData *) sink->conn_private;

        n = send(tcp_data->sd, buf, len, flags);
	/*
	if (n > 0)
		((xspdConn_defStats *)sink->stats_private)->bytes_written += n;
	*/
	return n;
}

static int xspd_conn_tcp_read(xspdConn *src, void *buf, size_t len, int flags) {
	int n;
	xspdConn_tcpData *tcp_data = (xspdConn_tcpData *) src->conn_private;

	n = recv(tcp_data->sd, buf, len, flags);
	/*
	if (n > 0)
		((xspdConn_defStats *) src->stats_private)->bytes_read += n;
	*/
	return n;
}

static int xspd_conn_tcp_shutdown(xspdConn *conn, uint8_t direction) {
	xspdConn_tcpData *tcp_data = (xspdConn_tcpData *) conn->conn_private;

	pthread_mutex_lock(&(tcp_data->lock));
	{
		tcp_data->closed |= direction;
		if (tcp_data->closed == (XSPD_SEND_SIDE | XSPD_RECV_SIDE)) {
			gettimeofday(&(conn->end_time), NULL);
			conn->status = STATUS_UNCONNECTED;
		}
	}
	pthread_mutex_unlock(&(tcp_data->lock));

	if (direction == XSPD_SEND_SIDE) {
		xspd_info(10, "shutdown send side to \"%s\": %d", conn->description, tcp_data->sd);
		shutdown(tcp_data->sd, SHUT_WR);
	} else if (direction == XSPD_RECV_SIDE) {
		xspd_info(10, "shutdown recv side to \"%s\": %d", conn->description, tcp_data->sd);
		shutdown(tcp_data->sd, SHUT_RD);
	} else if (direction == (XSPD_RECV_SIDE | XSPD_SEND_SIDE)) {
		xspd_info(10, "closed connection to \"%s\": %d", conn->description, tcp_data->sd);
		close(tcp_data->sd);
	} else {
		return -1;
	}

	return 0;
}

static int xspd_conn_tcp_setbufsize(xspdConn *conn, uint8_t direction, int size) {
	xspdConn_tcpData *tcp_data = (xspdConn_tcpData *) conn->conn_private;
	int new_bufsize;
	int n;
	SOCKLEN_T junk;

	if (direction & XSPD_RECV_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_RCVBUF, (const void *)&size, sizeof(int))) < 0) {
			xspd_err(10, "set recv buf of \"%s\" failed", conn->description);
			goto error_exit;
		}

		n = getsockopt(tcp_data->sd, SOL_SOCKET, SO_RCVBUF, (char *)&new_bufsize, (SOCKLEN_T *) &junk);
		if (n == 0) {
			xspd_info(5, "set recv buf of \"%s\" to \"%d\"",
					conn->description,
					new_bufsize);
		}
	}

	if (direction & XSPD_SEND_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_SNDBUF, (const void *)&size, sizeof(int))) < 0) {
			xspd_err(10, "set send buf of \"%s\" failed", conn->description);
			goto error_exit;
		}

		n = getsockopt(tcp_data->sd, SOL_SOCKET, SO_SNDBUF, (char *)&new_bufsize, (SOCKLEN_T *) &junk);
		if (n == 0) {
			xspd_info(5, "set send buf of \"%s\" to \"%d\"",
					conn->description,
					new_bufsize);
		}

	}
	
	return 0;

error_exit:
	return -1;
}

static int xspd_conn_tcp_settimeout(xspdConn *conn, uint8_t direction, int seconds) {
	xspdConn_tcpData *tcp_data = (xspdConn_tcpData *) conn->conn_private;
	struct timeval new_to;

	new_to.tv_sec = seconds;
	new_to.tv_usec = 0;

	if (direction & XSPD_RECV_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_RCVTIMEO, &new_to, sizeof(struct timeval))) < 0) {
			xspd_err(5, "failed to set recv timeout of \"%s\" to \"%d\"",
					conn->description,
					seconds);
			goto error_exit;
		}

	} 
	
	if (direction & XSPD_SEND_SIDE) {

		if ((setsockopt(tcp_data->sd, SOL_SOCKET, SO_SNDTIMEO, &new_to, sizeof(struct timeval))) < 0) {
			xspd_info(5, "failed to set send timeout of \"%s\" to \"%d\"",
					conn->description,
					seconds);
			goto error_exit;
		}

	}

	return 0;

error_exit:
	return -1;
}

static void xspd_conn_tcp_free_tcp_data(xspdConn *conn) {
	free(conn->conn_private);
}


#ifdef HAVE_WEB100

static int xspd_conn_tcp_web100_write(xspdConn *sink, const void *buf, size_t len, int flags) {
	return send(((xspdConn_tcpData *) sink->conn_private)->sd, buf, len, flags);
}

static int xspd_conn_tcp_web100_read(xspdConn *src, void *buf, size_t len, int flags) {
	return recv(((xspdConn_tcpData *) src->conn_private)->sd, buf, len, flags);
}

#endif
