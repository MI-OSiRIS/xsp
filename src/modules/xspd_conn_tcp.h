#ifndef XSPD_IO_TCP_H
#define XSPD_IO_TCP_H

#include <pthread.h>

#include "xspd_conn.h"

typedef struct xspd_connection_tcp_data_t {
	pthread_mutex_t lock;
	int closed;
	int sd;
} xspdConn_tcpData;

xspdConn *xspd_conn_tcp_alloc(int sd, int use_web100);

#endif
