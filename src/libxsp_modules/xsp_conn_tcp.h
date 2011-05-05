#ifndef XSP_IO_TCP_H
#define XSP_IO_TCP_H

#include <pthread.h>

#include "xsp_conn.h"

typedef struct xsp_connection_tcp_data_t {
	pthread_mutex_t lock;
	int closed;
	int sd;
} xspConn_tcpData;

xspConn *xsp_conn_tcp_alloc(int sd, int use_web100);

#endif
