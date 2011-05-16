#ifndef XSP_WEB100_H
#define XSP_WEB100_H

#include "xsp_conn.h"
#include <web100/web100.h>
#include <pthread.h>

typedef struct xsp_connection_web100_stats {
	web100_agent *agent;
	web100_connection *conn;

	uint8_t closed;
	pthread_mutex_t lock;

	int saved_state;
	float rtt;
	uint64_t bytes_in;
	uint64_t bytes_out;
	uint32_t bytes_retr;
} xspConn_web100Stats;

int xsp_web100_init();
xspConn_web100Stats *xsp_alloc_web100_stats(int sd);
void xsp_web100_free_stats(void *arg);
int xsp_web100_get_stat(xspConn *conn, uint16_t type, void *optval, SOCKLEN_T *optlen);
int xsp_web100_get_var(int sockfd, char *varname, void *opt, int *optlen);
void xsp_web100_save_stats(xspConn *conn, xspConn_web100Stats *stats);

#endif
