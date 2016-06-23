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
#ifndef LIBXSP_INTERFACE_H
#define LIBXSP_INTERFACE_H

#include <sys/queue.h>

#include "libxsp.h"
#include "libxsp_client_common.h"

#ifdef HAVE_SSH
#include "libssh2.h"
#endif

#ifdef NETLOGGER
#define MAX_FD 256
#endif

#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#include <openssl/ssl.h>
#endif

/* Objects */
typedef struct libxsp_sess_info_t {
        char sess_id[2*XSP_SESSIONID_LEN + 1];

        struct xsp_addr src_eid;
        struct xsp_addr dst_eid;

        uint32_t sess_flags;
        uint32_t hop_flags;

        xspHop **child;
        int child_count;	

	// the above is "inherited" from xspSess

        uint8_t version;
        uint8_t flags;
        uint16_t type;

	int sock;
	int data_sock;
	int connected;
	int data_connected;
	int sock_desc;

	char data_hop[XSP_HOPID_LEN];

	LIST_ENTRY(libxsp_sess_info_t) sessions;
	
	ssize_t (*sendfn) (struct libxsp_sess_info_t *sess, const void *buf, size_t len, int flags);
	ssize_t (*recvfn) (struct libxsp_sess_info_t *sess, void *buf, size_t len, int flags);
			
	enum xsp_sec security;
	xspSecInfo *sec_info;
	
#ifdef HAVE_SSH
	LIBSSH2_SESSION *ssh_sess;
	LIBSSH2_CHANNEL *ssh_chan;
	LIBSSH2_AGENT *agent;
#endif

#ifdef HAVE_OPENSSL
	SSL_CTX *ctx;
	BIO *sbio;
	SSL *ssl;
#endif

#ifdef HAVE_GLOBUS
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
int xsp_sess_set_security(libxspSess *sess, xspSecInfo *sec, int type);

xspSecInfo *xsp_sess_new_security(char *username, char *password, char *privkey, char *pubkey, char *keypass);
xspNetPath *xsp_sess_new_net_path(int action);
xspNetPathRule *xsp_sess_new_net_path_rule(xspNetPath *path, char *type);
int xsp_sess_set_net_path_rule_crit(xspNetPathRule *rule, libxspNetPathRuleCrit *crit);
int xsp_sess_set_net_path_rule_eid(xspNetPathRule *rule, void *eid, int type);
int xsp_sess_set_net_path_rule_op(xspNetPathRule *rule, int op);

int xsp_signal_inf_data(libxspSess *sess);
int xsp_signal_path(libxspSess *sess, xspNetPath *net_path);

int xsp_connect(libxspSess *sess);
int xsp_data_connect(libxspSess *sess);
int xsp_setsockopt(libxspSess *sess, int level, int optname, const void *optval, socklen_t optlen);
int xsp_getsockopt(libxspSess *sess, int level, int optname, void *optval, socklen_t *optlen);
int xsp_close(libxspSess *sess);
ssize_t xsp_send(libxspSess *sess, const void *buf, size_t len, int flags);
ssize_t xsp_recv(libxspSess *sess, void *buf, size_t len, int flags);
int xsp_send_msg(libxspSess *sess, const void *buf, uint64_t len, int opt_type);
int xsp_recv_msg(libxspSess *sess, void **ret_buf, uint64_t *len, int *ret_type);
int xsp_wait_ack(libxspSess *sess);
int xsp_shutdown(libxspSess *sess, int how);
int xsp_get_session_socket(libxspSess *sess);
int xsp_set_session_socket(libxspSess *sess, int new_sd);

#endif
