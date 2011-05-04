#ifndef XSPD_CONN_H
#define XSPD_CONN_H

#include "config.h"

#include <sys/time.h>
#include <fcntl.h>

#include "queue.h"
#include "libxsp_proto.h"
#include "xspd_settings.h"

enum xspd_connection_status_t { STATUS_UNCONNECTED, STATUS_CONNECTED, STATUS_FROZEN };

typedef struct xspd_connection_t {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	enum xspd_connection_status_t status;
	LIST_ENTRY(xspd_connection_t) channel_entries;
	LIST_ENTRY(xspd_connection_t) sess_entries;
	struct xspd_session_t *session;
	char *id;
	char *hostname;
	char *description;
	char *protocol;
	
	struct xspd_path_t *path;
	struct xspd_channel_t *channel;
	
	xspdSettings *settings;
	struct timeval start_time, end_time;

	
	int (*splice2) (struct xspd_connection_t *src, struct xspd_connection_t *sink, size_t len, int flags);
	int (*src_splice2) (struct xspd_connection_t *conn, int fd, size_t len, int flags);
	int (*sink_splice2) (struct xspd_connection_t *conn, int fd, size_t len, int flags);
	int (*read2) (struct xspd_connection_t *src, void *buf, size_t len, int flags);
	int (*write2) (struct xspd_connection_t *sink, const void *buf, size_t len, int flags);
	int (*shutdown2) (struct xspd_connection_t *conn, uint8_t direction);
	int (*setbufsize2) (struct xspd_connection_t *conn, uint8_t direction, int size);
	int (*settimeout2) (struct xspd_connection_t *conn, uint8_t direction, int seconds);
	void (*free_conn_private2) (struct xspd_connection_t *conn);
				     //void (*free_stats2) (void *arg);

	xspMsg *(*get_msg2) (struct xspd_connection_t *conn, unsigned int flags);
	int (*send_msg2) (struct xspd_connection_t *conn, uint8_t type, void *msg_body);

				     //int (*get_stat2) (struct xspd_connection_t *conn, uint16_t type, void *optval, size_t *optlen);

	void *auth_info;

	void *conn_private;

	void *stats_private;
} xspdConn;

typedef struct xspd_conn_stats_default_t {
	struct timeval connect_time;
	struct timeval shutdown_read_time;
	struct timeval shutdown_write_time;
	uint64_t bytes_read;
	uint64_t bytes_written;
} xspdConn_defStats;

#define XSPD_SEND_SIDE	0x01
#define XSPD_RECV_SIDE	0x02

//xspdConn_defStats *xspd_conn_stats_alloc_def();
xspdConn *xspd_conn_alloc();
void xspd_conn_free(xspdConn *conn);
void __xspd_conn_free(xspdConn *conn);
//void xspd_conn_free_stats_def(xspdConn *conn);
//int xspd_conn_default_get_stat(xspdConn *conn, uint16_t type, void *optval, size_t *optlen);
xspMsg *xspd_conn_default_get_msg(xspdConn *conn, unsigned int flags);
int xspd_conn_default_send_msg(xspdConn *conn, uint8_t type, void *msg_body);

int xspd_conn_src_splice(xspdConn *conn, int fd, size_t len, int flags);
int xspd_conn_sink_splice(xspdConn *conn, int fd, size_t len, int flags);
int xspd_conn_read(xspdConn *conn, void *buf, size_t len, int flags);
int xspd_conn_write(xspdConn *conn, const void *buf, size_t len, int flags);
int xspd_conn_setbufsize(xspdConn *conn, uint8_t direction, int size);
int xspd_conn_settimeout(xspdConn *conn, uint8_t direction, int seconds);
int xspd_conn_shutdown(xspdConn *conn, int side);
xspMsg *xspd_conn_get_msg(xspdConn *conn, unsigned int flags);
int xspd_conn_send_msg(xspdConn *conn, uint8_t type, void *msg_body);
//int xspd_conn_get_stat (xspdConn *conn, uint16_t type, void *optval, size_t *optlen);


#endif
