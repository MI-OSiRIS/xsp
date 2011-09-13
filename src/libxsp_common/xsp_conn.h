#ifndef XSP_CONN_H
#define XSP_CONN_H

#include "config.h"

#include <sys/time.h>
#include <fcntl.h>

#include "queue.h"
#include "libxsp_proto.h"
#include "xsp_settings.h"

enum xsp_connection_status_t { STATUS_UNCONNECTED, STATUS_CONNECTED, STATUS_FROZEN };
enum xsp_peer_type_t { EDGE_PEER = 0, STREAM_PEER, SLABS_PEER };

typedef struct xsp_connection_t {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	enum xsp_connection_status_t status;
	LIST_ENTRY(xsp_connection_t) channel_entries;
	LIST_ENTRY(xsp_connection_t) sess_entries;
	struct common_session_t *session;
	char *id;
	char *hostname;
	char *addr;
	char *description;
	char *protocol;
	int xsp_peer;
	
	struct xsp_path_t *path;
	struct xsp_channel_t *channel;
	
	xspSettings *settings;
	struct timeval start_time, end_time;
	
	int (*splice2) (struct xsp_connection_t *src, struct xsp_connection_t *sink, size_t len, int flags);
	int (*src_splice2) (struct xsp_connection_t *conn, int fd, size_t len, int flags);
	int (*sink_splice2) (struct xsp_connection_t *conn, int fd, size_t len, int flags);
	int (*read2) (struct xsp_connection_t *src, void *buf, size_t len, int flags);
	int (*write2) (struct xsp_connection_t *sink, const void *buf, size_t len, int flags);
	int (*set_session_status2) (struct xsp_connection_t *sink, int status);
	int (*shutdown2) (struct xsp_connection_t *conn, uint8_t direction);
	int (*setbufsize2) (struct xsp_connection_t *conn, uint8_t direction, int size);
	int (*settimeout2) (struct xsp_connection_t *conn, uint8_t direction, int seconds);
	void (*free_conn_private2) (struct xsp_connection_t *conn);
	void (*free_stats2) (struct xsp_connection_t *conn);
	
	xspMsg *(*get_msg2) (struct xsp_connection_t *conn, unsigned int flags);
	uint64_t (*send_msg2) (struct xsp_connection_t *conn, struct xsp_message_t *msg, struct xsp_block_list_t *bl);
	
	int (*get_stat2) (struct xsp_connection_t *conn, uint16_t type, void *optval, size_t *optlen);

	void *auth_info;

	void *conn_private;

	void *stats_private;
} xspConn;

typedef struct xsp_conn_stats_default_t {
	struct timeval connect_time;
	struct timeval shutdown_read_time;
	struct timeval shutdown_write_time;
	uint64_t bytes_read;
	uint64_t bytes_written;
} xspConn_defStats;

#define XSP_SEND_SIDE	0x01
#define XSP_RECV_SIDE	0x02

xspConn_defStats *xsp_conn_stats_alloc_def();
xspConn *xsp_conn_alloc();
void xsp_conn_free(xspConn *conn);
void __xsp_conn_free(xspConn *conn);
void *xsp_conn_get_priv_data(xspConn *conn);
void xsp_conn_free_stats_def(xspConn *conn);
int xsp_conn_default_get_stat(xspConn *conn, uint16_t type, void *optval, size_t *optlen);
xspMsg *xsp_conn_default_get_msg(xspConn *conn, unsigned int flags);
uint64_t xsp_conn_default_send_msg(xspConn *conn, xspMsg *msg, xspBlockList *bl);
int xsp_conn_default_set_session_status(xspConn *conn, int status);

int xsp_conn_src_splice(xspConn *conn, int fd, size_t len, int flags);
int xsp_conn_sink_splice(xspConn *conn, int fd, size_t len, int flags);
int xsp_conn_read(xspConn *conn, void *buf, size_t len, int flags);
int xsp_conn_write(xspConn *conn, const void *buf, size_t len, int flags);
int xsp_conn_setbufsize(xspConn *conn, uint8_t direction, int size);
int xsp_conn_settimeout(xspConn *conn, uint8_t direction, int seconds);
int xsp_conn_shutdown(xspConn *conn, int side);
xspMsg *xsp_conn_get_msg(xspConn *conn, unsigned int flags);
uint64_t xsp_conn_send_msg(xspConn *conn, xspMsg *msg, uint16_t opt_type);
int xsp_conn_get_stat (xspConn *conn, uint16_t type, void *optval, size_t *optlen);

#endif
