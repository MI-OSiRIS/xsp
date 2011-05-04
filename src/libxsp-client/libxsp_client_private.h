#ifndef LIBXSP_INTERFACE_H
#define LIBXSP_INTERFACE_H

#include <sys/queue.h>

#include "libxsp.h"

#ifdef NETLOGGER
#define MAX_FD 256
#endif

/* Objects */
typedef struct libxsp_sess_info_t {
	char sess_id[XSP_SESSIONID_LEN * 2 + 1];

	char src_id[XSP_HOPID_LEN + 1];
	char dst_id[XSP_HOPID_LEN + 1];

	uint32_t sess_flags;

	uint32_t hop_flags;

	xspHop **child;
	int child_count;

	// the above is "inherited" from xspSess

	int sock;
	int data_sock;
	int connected;
	int data_connected;
	int sock_desc;

	char data_hop[XSP_HOPID_LEN];

	LIST_ENTRY(libxsp_sess_info_t) sessions;

#ifdef USE_GLOBUS
	gss_ctx_id_t ctx_handle;
#endif

#ifdef NETLOGGER
	unsigned long long block_id;
	int nl_id;
#endif

	int mtu;
	int debug;
	int nodelay;
	int reuseaddr;
	int recv_bufsize;
	int send_bufsize;
	int recv_timeout;
	int send_timeout;

	struct sockaddr end_host_addr;
	SOCKLEN_T end_host_addrlen;

	xspHop *prev_added_child;
} libxspSess;

int libxsp_init(void);
libxspSess *xsp_session();
int xsp_sess_appendchild(libxspSess *sess, char *child, unsigned int flags);
int xsp_sess_addchild(libxspSess *sess, char *parent, char *child, uint16_t flags);
int xsp_connect(libxspSess *sess);
int xsp_signal_path(libxspSess *sess, char *path_type);
int xsp_setsockopt(libxspSess *sess, int level, int optname, const void *optval, socklen_t optlen);
int xsp_getsockopt(libxspSess *sess, int level, int optname, void *optval, socklen_t *optlen);
int xsp_close(libxspSess *sess);
ssize_t xsp_send(libxspSess *sess, const void *buf, size_t len, int flags);
ssize_t xsp_recv(libxspSess *sess, void *buf, size_t len, int flags);
int xsp_shutdown(libxspSess *sess, int how);
int xsp_get_session_socket(libxspSess *sess);
int xsp_set_session_socket(libxspSess *sess, int new_sd);

#endif
