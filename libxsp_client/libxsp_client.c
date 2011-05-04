#include "config.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "libxsp.h"
#include "libxsp_hop.h"
#include "libxsp_proto.h"
#include "libxsp_client_private.h"

#ifdef HAVE_GLOBUS
#include "globus_gss_assist.h"
#endif

#include "compat.h"

/* Functions */
int libxsp_init();
void xsp_globus_init(void);
libxspSess *xsp_session();
int xsp_add_sess(int s, libxspSess *sess);
int xsp_del_sess(libxspSess *sess);
int __xsp_addchild(xspHop *curr_node, char *parent, xspHop *new_child);
int xsp_put_msg(libxspSess *sess, uint8_t version, uint8_t type, char *sess_id, void *msg_body);
xspMsg *xsp_get_msg(libxspSess *sess, unsigned int flags);
int xsp_sess_appendchild(libxspSess *sess, char *child, unsigned int flags);
int xsp_data_connect(libxspSess *sess);
static int xsp_hash_password(const unsigned char *pass, unsigned int pass_len, const unsigned char *nonce, unsigned char *ret_hash);

#ifdef HAVE_GLOBUS
int xsp_globus_get_token( void *arg, void ** token, size_t * token_length);
int xsp_globus_send_token( void *arg, void * token, size_t token_length);
#endif

/* Local Variables */
static pthread_once_t init_once_globus = PTHREAD_ONCE_INIT;

#ifdef HAVE_GLOBUS
static gss_cred_id_t client_cred_handle = GSS_C_NO_CREDENTIAL;
#endif

static int (*std_socket)(int, int, int);
static int (*std_connect)(int, const struct sockaddr *, SOCKLEN_T); 
static int (*std_setsockopt)(int, int, int, const void *, SOCKLEN_T);
static int (*std_getsockopt)(int, int, int, void *, SOCKLEN_T *); 
static int (*std_close)(int);
static ssize_t (*std_send)(int, const void *, size_t, int);
static ssize_t (*std_recv)(int, void *, size_t, int);
static int (*std_shutdown)(int, int);

int libxsp_init() {
	void *handle;
	const char *error;
	long int seed;

	d_printf(" > libxsp_init()\n");

	seed = gen_rand_seed();

	d_printf("libxsp_init(): seeding RNG with %li\n", seed);

	srand48(seed);

#ifdef __APPLE__
	// open up the standard library
        handle = dlopen("libgcc_s.1.dylib", RTLD_LAZY);
        if (!handle) {
                d_printf("libxsp_init(): couldn't load libgc: %s\n", dlerror());
                goto error_exit;
        }
#else
	// open up the standard library
	handle = dlopen("libc.so.6", RTLD_LAZY);
	if (!handle) {
		d_printf("libxsp_init(): couldn't load libc: %s\n", dlerror());
		goto error_exit;
	}
#endif
	// find the socket symbol
	std_socket = (int (*)(int, int, int)) dlsym(handle, "socket");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading socket symbol: %s\n", error);
		goto error_exit2;
	}

	// find the connect symbol
	std_connect = (int (*)(int, const struct sockaddr *, SOCKLEN_T)) dlsym(handle, "connect");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading connect symbol: %s\n", error);
		goto error_exit2;
	}

	// find the setsockopt symbol
	std_setsockopt = (int (*)(int, int, int, const void *, SOCKLEN_T)) dlsym(handle, "setsockopt");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading setsockopt symbol: %s\n", error);
		goto error_exit2;
	}

	// find the getsockopt symbol
	std_getsockopt = (int (*)(int, int, int, void *, SOCKLEN_T *)) dlsym(handle, "getsockopt");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading getsockopt symbol: %s\n", error);
		goto error_exit2;
	}

	std_close = (int (*)(int)) dlsym(handle, "close");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_shutdown = (int (*)(int,int)) dlsym(handle, "shutdown");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_send = (ssize_t (*)(int,const void *,size_t,int)) dlsym(handle, "send");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_recv = (ssize_t (*)(int,void *,size_t,int)) dlsym(handle, "recv");
	if ((error = dlerror()) != NULL) {
		d_printf("libxsp_init(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}
	
	if (xsp_init() < 0) {
		d_printf("libxsp_init(): error initializing protocol handler\n");
		goto error_exit2;
	}
	
	d_printf(" < leaving libxsp_init()\n");

	return 0;

error_exit2:
	dlclose(handle);
error_exit:
	return -1;
}

#ifdef HAVE_GLOBUS
void xsp_globus_init(void) {
	OM_uint32 major, minor;

	major = globus_module_activate(GLOBUS_COMMON_MODULE);
	if (major != GLOBUS_SUCCESS) {
		globus_gss_assist_display_status(stderr, "failed to initialize globus", major, minor, 0);
		exit(-1);
	}

	major = globus_gss_assist_acquire_cred(&minor, GSS_C_BOTH, &client_cred_handle);
	if (major != GSS_S_COMPLETE) {
		globus_gss_assist_display_status(stderr, "failed to obtained credentials", major, minor, 0);
		return;
	}
}
#else
// do nothing if globus isn't enabled
void xsp_globus_init(void) { }
#endif

libxspSess *xsp_session() {
	libxspSess *new_sess;

	new_sess = (libxspSess *) malloc(sizeof(libxspSess));
	if (!new_sess)
		return NULL;

	bzero(new_sess, sizeof(libxspSess));

#ifdef NETLOGGER
	new_sess->block_id = 0;
#endif

	return new_sess;
}

int xsp_sess_appendchild(libxspSess *sess, char *child, unsigned int flags) {
	xspHop *hop;

	hop = xsp_alloc_hop(child, strlen(child));
	if (!hop) {
		d_printf("xsp_sess_appendchild(): failed to allocate child structure\n");
		errno = ENOMEM;
		return -1;
	}

	strlcpy(hop->hop_id, child, sizeof(hop->hop_id));
	hop->session = (xspSess *) sess;
	hop->flags = flags;

	if (sess->prev_added_child == NULL) {
		d_printf("xsp_sess_appendchild(): adding first child: \"%s\"\n", child);

		sess->child = (xspHop **) malloc(sizeof(xspHop *));
		if (!sess->child) {
			d_printf("xsp_sess_appendchild(): failed to allocate space for child pointer\n");
			goto error_exit;
		}

		sess->child[0] = hop;
		sess->child_count = 1;

	} else if (!(sess->prev_added_child->flags & XSP_HOP_NATIVE)) {
		d_printf("xsp_sess_appendchild(): error: trying to add a child to a non-xsp speaking node\n");
		goto error_exit;
	} else {
		d_printf("xsp_sess_appendchild(): adding \"%s\" as child of \"%s\"\n", child, sess->prev_added_child->hop_id);
		sess->prev_added_child->child = (xspHop **) malloc(sizeof(xspHop *));
		if (!sess->prev_added_child->child) {
			d_printf("xsp_sess_appendchild(): failed to allocate space for child pointer\n");
			goto error_exit;
		}

		sess->prev_added_child->child[0] = hop;
		sess->prev_added_child->child_count = 1;
	}

	sess->prev_added_child = hop;

	return 0;

error_exit:
	free(hop);
	return -1;
}

int xsp_sess_addchild(libxspSess *sess, char *parent, char *child, uint16_t flags) {
	xspHop *hop;
	int i;
	int retval = -1;
	xspHop **new_list;

	hop = xsp_alloc_hop(child, strlen(child));
	if (!hop) {
		d_printf("xsp_sess_addchild(): failed to allocate child structure\n");
		errno = ENOMEM;
		return -1;
	}

	strlcpy(hop->hop_id, child, sizeof(hop->hop_id));
	hop->session = (xspSess *) sess;
	hop->flags = flags;

	if (!strcmp(parent, "")) {
		new_list = (xspHop **) realloc(sess->child, sizeof(xspHop *) * (sess->child_count + 1));
		if (!new_list) {
			d_printf("xsp_sess_addchild(): failed to resize list of child pointers\n");
			errno = ENOMEM;
			return -1;
		}

		sess->child = new_list;
		sess->child[sess->child_count] = hop;
		sess->child_count++;
		return 1;
	}

	for(i = 0; i < sess->child_count; i++) {
		retval = __xsp_addchild(sess->child[i], parent, hop);

		if (retval < 0 || retval == 1)
			break;
	}

	if (retval == 1)
		sess->prev_added_child = hop;
	else
		xsp_free_hop(hop, 0);

	return retval;
}

int __xsp_addchild(xspHop *curr_node, char *parent, xspHop *new_child) {
	int i;
	int retval = -1;

	if (!strcmp(curr_node->hop_id, parent)) {
		xspHop **new_list;

		if (!(curr_node->flags & XSP_HOP_NATIVE)) {
			d_printf("__xsp_addchild(): attempting to add \"%s\" as child of non-xsp node \"%s\"\n", new_child->hop_id, parent);
			return -1;
		}


		new_list = (xspHop **) realloc(curr_node->child, (curr_node->child_count + 1) * sizeof(xspHop *));
		if (!new_list) {
			d_printf("__xsp_addchild(): failed to resize list of child pointers\n");
			return -1;
		}

		curr_node->child = new_list;

		curr_node->child[curr_node->child_count] = new_child;

		curr_node->child_count++;

		return 1;
	}

	for(i = 0; i < curr_node->child_count; i++) {
		retval = __xsp_addchild(curr_node->child[i], parent, new_child);
		if (retval == 1 || retval < 0)
			break;
	}

	return retval;
}

int xsp_connect(libxspSess *sess) {
	int r = -1;
	struct addrinfo *nexthop_addrs = NULL;
	struct addrinfo *nexthop = NULL;
	int connected;
	int connfd = -1;
	xspHop *next_hop;
#ifdef HAVE_GLOBUS
	OM_uint32 major = 0, minor = 0, ret_flags = 0;
	int token_status = 0;
	FILE *socket_desc;
#endif

	pthread_once(&init_once_globus, xsp_globus_init);

	// generate a random session id
	gen_rand_hex(sess->sess_id, 2*XSP_SESSIONID_LEN+1);

	d_printf("xsp_connect(): new session id: %s\n", sess->sess_id);

	if (sess->child_count > 1) {
		d_printf("xsp_connect(): error: can't send to multiple hosts yet\n");
		errno = EAFNOSUPPORT;
		return -1;
	}

	next_hop = sess->child[0];

	nexthop_addrs = xsp_lookuphop(next_hop->hop_id);
	if (!nexthop_addrs) {
		d_printf("xsp_connect(): error: next hop lookup failed: %s\n", next_hop->hop_id);
		errno = ENETUNREACH;
		return -1;
	}

	connected = 0;

	for(nexthop = nexthop_addrs; nexthop != NULL && connected == 0; nexthop = nexthop->ai_next) {
		connfd = std_socket(nexthop->ai_family, nexthop->ai_socktype, nexthop->ai_protocol);
		if (connfd < 0) {
			d_printf("xsp_connect(): warning: socket failed for %s: %s\n", next_hop->hop_id, strerror(errno));
			continue;
		}

		r = std_connect(connfd, nexthop->ai_addr, nexthop->ai_addrlen);
		if (r < 0) {
			d_printf("xsp_connect(): connect failed: %s\n", strerror(errno)); 
			std_close(connfd);
			continue;
		}

		connected = 1;
	}

	freeaddrinfo(nexthop_addrs);

	if (connected == 0) {
		d_printf("xsp_connect(): couldn't connect to destination host\n");
		errno = ECONNREFUSED;
		return -1;
	}
	
	sess->sock = connfd;

	if (next_hop->flags & XSP_HOP_NATIVE) {
		xspMsg *msg;
		xspAuthType auth_type;
		xspAuthToken token, *ret_token;


#ifndef HAVE_GLOBUS
		if (getenv("XSP_USERNAME") && getenv("XSP_PASSWORD")) {
			unsigned char hash[SHA_DIGEST_LENGTH];
			strlcpy(auth_type.name, "PASS", XSP_AUTH_NAME_LEN);
			if (xsp_put_msg(sess, 0, XSP_MSG_AUTH_TYPE, sess->sess_id, &auth_type) < 0) {
				d_printf("xsp_connect(): error: PASS authorization failed: couldn't send auth type\n");
				errno = ECONNREFUSED;
				std_close(connfd);
				return -1;
			}

			token.token = getenv("XSP_USERNAME");
			token.token_length = strlen(getenv("XSP_USERNAME"));

			if (xsp_put_msg(sess, 0, XSP_MSG_AUTH_TOKEN, sess->sess_id, &token) < 0) {
				d_printf("xsp_connect(): error: PASS authorization failed: couldn't send username\n");
				errno = ECONNREFUSED;
				std_close(connfd);
				return -1;
			}

			msg = xsp_get_msg(sess, 0);
			if (!msg || msg->type != XSP_MSG_AUTH_TOKEN) {
				if (msg)
					xsp_free_msg(msg);
				d_printf("xsp_connect(): error: PASS authorization failed: received invalid rxsponse\n");
				errno = ECONNREFUSED;
				std_close(connfd);
				return -1;
			}

			ret_token = msg->msg_body;

			if (ret_token->token_length != SHA_DIGEST_LENGTH) {
				xsp_free_msg(msg);
				d_printf("xsp_connect(): error: PASS authorization failed: received invalid rxsponse(not a sha1 hash)\n");
				errno = ECONNREFUSED;
				std_close(connfd);
				return -1;
			}

			xsp_hash_password(getenv("XSP_PASSWORD"), strlen(getenv("XSP_PASSWORD")), ret_token->token, hash);

			token.token = hash;
			token.token_length = SHA_DIGEST_LENGTH;

			if (xsp_put_msg(sess, 0, XSP_MSG_AUTH_TOKEN, sess->sess_id, &token) < 0) {
				d_printf("xsp_connect(): error: PASS authorization failed: couldn't send password hash\n");
				errno = ECONNREFUSED;
				std_close(connfd);
				return -1;
			}
		} else {
			strlcpy(auth_type.name, "ANON", XSP_AUTH_NAME_LEN);
			if (xsp_put_msg(sess, 0, XSP_MSG_AUTH_TYPE, sess->sess_id, &auth_type) < 0) {
				d_printf("xsp_connect(): error: authorization failed\n");
				errno = ECONNREFUSED;
				std_close(connfd);
			}
		}
#else
		auth_info.type = 1;
		if (xsp_put_msg(sess, 0, XSP_MSG_AUTHORIZATION_START, sess->sess_id, &auth_info) < 0) {
			d_printf("Error: authorization failed\n");
			errno = ECONNREFUSED;
			std_close(connfd);
		}

		ret_flags = 0;
		token_status = 0;
		socket_desc = fdopen(sockfd, "w+");

		major = globus_gss_assist_init_sec_context(
				&minor,
				client_cred_handle,
				&sess->ctx_handle,
				NULL,
				GSS_C_DELEG_FLAG,
				&ret_flags,
				&token_status,
				xsp_globus_get_token,
				(void *) &sockfd,
				xsp_globus_send_token,
				(void *) &sockfd);

		if (major != GSS_S_COMPLETE) {
			globus_gss_assist_display_status(stderr, "XSP authentication failure\n", major, minor, token_status);
		}
#endif

		if (xsp_put_msg(sess, 0, XSP_MSG_SESS_OPEN, sess->sess_id, next_hop) < 0) {
			d_printf("xsp_connect(): error: failed to send session open message\n");
			std_close(connfd);
			errno = ECONNREFUSED;
			return -1;
		}

		if (getenv("XSP_CIRCUIT") != NULL) {
			d_printf("xsp_connect(): found XSP_CIRCUIT, using %s\n", getenv("XSP_CIRCUIT"));
			if (xsp_signal_path(sess, getenv("XSP_CIRCUIT")) != 0) {
				fprintf(stderr, "xsp_connect(): could not signal XSP_CIRCUIT\n");
			}
		}
		
		msg = xsp_get_msg(sess, 0);
		if (!msg) {
			d_printf("xsp_connect(): error: did not receive a valid response\n");
			std_close(connfd);
			errno = ECONNREFUSED;
			return -1;
		}

		if (msg->type == XSP_MSG_SESS_NACK) {
			fprintf(stderr, "xsp_connect(): could not connect to destination using XSP, error received: %s\n", (char *) msg->msg_body);
			std_close(connfd);
			errno = ECONNREFUSED;
			return -1;
		} else if (msg->type != XSP_MSG_SESS_ACK) {
			d_printf("xsp_connect(): error: did not receive a session ACK\n");
			std_close(connfd);
			errno = ECONNREFUSED;
			return -1;
		}

		free(msg);
	}
	
	d_printf("xsp_connect(): session connected\n");
	sess->connected = 1;

	return 0;
}

int xsp_data_connect(libxspSess *sess) {
	int r = -1;
        struct addrinfo *nexthop_addrs = NULL;
        struct addrinfo *nexthop = NULL;
        int connected;
        int connfd = -1;

        nexthop_addrs = xsp_lookuphop(sess->data_hop);
        if (!nexthop_addrs) {
                d_printf("xsp_connect(): error: next hop lookup failed: %s\n", sess->data_hop);
                errno = ENETUNREACH;
                return -1;
        }

        connected = 0;

        for(nexthop = nexthop_addrs; nexthop != NULL && connected == 0; nexthop = nexthop->ai_next) {
                connfd = std_socket(nexthop->ai_family, nexthop->ai_socktype, nexthop->ai_protocol);
                if (connfd < 0) {
                        d_printf("xsp_connect(): warning: socket failed for %s: %s\n", sess->data_hop, strerror(errno));
                        continue;
                }

                if (sess->mtu != 0) {
                        int new_val;
                        SOCKLEN_T new_size = sizeof(new_val);

                        d_printf("xsp_connect(): setting mtu: %d\n", sess->mtu);

                        std_setsockopt(connfd, IPPROTO_TCP, TCP_MAXSEG, &(sess->mtu), sizeof(sess->mtu));

                        if (std_getsockopt(connfd, IPPROTO_TCP, TCP_MAXSEG, &new_val, &new_size) == 0) {
                                sess->mtu = new_val;
                                d_printf("xsp_connect(): mtu set to: %d\n", sess->mtu);
                        } else {
                                d_printf("xsp_connect(): failed to set mtu: %s\n", strerror(errno));
                        }
                }

                if (sess->nodelay) {
                        int one = 1;

                        d_printf("xsp_connect(): setting tcp_nodelay\n");

                        if (std_setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &(one), sizeof(one)) != 0) {
                                d_printf("xsp_connect(): failed to set tcp_nodelay\n");
                        }
                }

                if (sess->debug) {
                        int one = 1;

                        d_printf("xsp_connect(): setting so_debug\n");

                        if (std_setsockopt(connfd, SOL_SOCKET, SO_DEBUG, &(one), sizeof(one)) != 0) {
                                d_printf("xsp_connect(): failed to set so_debug\n");
                        }
                }

                if (sess->reuseaddr) {
                        int one = 1;

                        d_printf("xsp_connect(): setting so_reuseaddr\n");

                        if (std_setsockopt(connfd, SOL_SOCKET, SO_REUSEADDR, &(one), sizeof(one)) != 0) {
                                d_printf("xsp_connect(): failed to set so_reuseaddr\n");
                        }
                }

                if (sess->recv_timeout != 0) {
                        int new_val;
                        SOCKLEN_T new_size = sizeof(new_val);

                        d_printf("xsp_connect(): setting recv timeout: %d\n", sess->recv_timeout);

                        std_setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &(sess->recv_timeout), sizeof(sess->recv_timeout));

                        if (std_getsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &new_val, &new_size) == 0) {
                                sess->recv_timeout = new_val;
                                d_printf("xsp_connect(): recv timeout set to: %d\n", sess->recv_timeout);
                        } else {
                                d_printf("xsp_connect(): failed to set recv timeout: %s\n", strerror(errno));
                        }
                }

                if (sess->send_timeout != 0) {
                        int new_val;
                        SOCKLEN_T new_size = sizeof(new_val);

                        d_printf("xsp_connect(): setting send timeout: %d\n", sess->send_timeout);

                        std_setsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, &(sess->send_timeout), sizeof(sess->send_timeout));

                        if (std_getsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, &new_val, &new_size) == 0) {
                                sess->send_timeout = new_val;
                                d_printf("xsp_connect(): send timeout set to: %d\n", sess->send_timeout);
                        } else {
                                d_printf("xsp_connect(): failed to set send timeout: %s\n", strerror(errno));
                        }
                }

                if (sess->send_bufsize != 0) {
                        int new_val;
                        SOCKLEN_T new_size = sizeof(new_val);

                        d_printf("xsp_connect(): setting send buffer: %d\n", sess->send_bufsize);

                        std_setsockopt(connfd, SOL_SOCKET, SO_SNDBUF, &(sess->send_bufsize), sizeof(sess->send_bufsize));


                        if (std_getsockopt(connfd, SOL_SOCKET, SO_SNDBUF, &new_val, &new_size) == 0) {
                                sess->send_bufsize = new_val;
                                d_printf("xsp_connect(): send buffer set to: %d\n", sess->send_bufsize);
                        } else {
                                d_printf("xsp_connect(): failed to set send buffer: %s\n", strerror(errno));
                        }
                }

                if (sess->recv_bufsize != 0) {
                        int new_val;
                        SOCKLEN_T new_size = sizeof(new_val);

                        d_printf("xsp_connect(): setting recv buffer: %d\n", sess->recv_bufsize);

                        std_setsockopt(connfd, SOL_SOCKET, SO_RCVBUF, &(sess->recv_bufsize), sizeof(sess->recv_bufsize));

                        if (std_getsockopt(connfd, SOL_SOCKET, SO_RCVBUF, &new_val, &new_size) == 0) {
                                sess->recv_bufsize = new_val;
                                d_printf("xsp_connect(): recv buffer set to: %d\n", sess->recv_bufsize);
                        } else {
                                d_printf("xsp_connect(): failed to set recv buffer: %s\n", strerror(errno));
                        }
                }

                r = std_connect(connfd, nexthop->ai_addr, nexthop->ai_addrlen);
                if (r < 0) {
                        d_printf("xsp_connect(): connect failed: %s\n", strerror(errno));
                        std_close(connfd);
                        continue;
                }

                connected = 1;
        }

        if (connected == 0) {
                d_printf("xsp_connect(): couldn't connect to destination host\n");
                errno = ECONNREFUSED;
                return -1;
        }

        sess->data_sock = connfd;
        sess->data_connected = 1;

        return 0;
}

int xsp_send_msg(libxspSess *sess, const void *buf, size_t len, int opt_type) {
	xspBlockHeader block;
	int ret;

	block.type = (uint16_t)opt_type;
	block.sport = 0;
	block.length = len;
	block.blob = buf;

	if ((ret = xsp_put_msg(sess, 0, XSP_MSG_APP_DATA, sess->sess_id, &block)) < 0) {
		d_printf("xsp_send_msg(): error: failed to send message\n");
		goto error_exit;
	}

	return ret;

 error_exit:
	return 0;
}

int xsp_recv_msg(libxspSess *sess, void **ret_buf, int *len, int *ret_type) {
	xspMsg *msg;
	xspBlockHeader *block;

	msg = xsp_get_msg(sess, 0);
	
	if (!msg) {
		d_printf("xsp_recv_msg(): error: did not receive message\n");
		goto error_exit;
	}
	if (msg->type != XSP_MSG_APP_DATA) {
		d_printf("xsp_recv_msg(): error: did not receive XSP_MSG_APP_DATA message\n");
		goto error_exit;
	}
	
	block = (xspBlockHeader *) msg->msg_body;

	if (block->length <=0 ) {
	    d_printf("xsp_recv_msg(): error: no block data!\n");
	    goto error_exit;
	}

	*ret_buf = (void*)malloc(sizeof(char) * block->length);
	if (!ret_buf) {
	    d_printf("xsp_recv_msg(): could not allocate memory for return buffer!\n");
	    goto error_exit;
	}
	    
	memcpy(*ret_buf, block->blob, block->length);
	
	*ret_type = block->type;
	*len = block->length;
	
	return block->length;

 error_exit:
	*ret_buf = NULL;
	return 0;
}

int xsp_signal_path(libxspSess *sess, char *path_type) {
	xspMsg *msg;
	xspBlockHeader block;
	char *path;

	if (!strcmp(path_type, "TERAPATHS") ||
	    !strcmp(path_type, "OSCARS")) {
		
		path = strdup(path_type);
		block.type = 0;
		block.sport = 0;
		block.length = strlen(path) + 1;
		block.blob = path;

		if (xsp_put_msg(sess, 0, XSP_MSG_PATH_OPEN, sess->sess_id, &block) < 0) {
			d_printf("xsp_signal_path(): error: failed to send session path message\n");
			goto error_exit;
		}
		
		msg = xsp_get_msg(sess, 0);
		if (!msg) {
			d_printf("xsp_signal_path(): error: did not receive a valid response\n");
			goto error_exit;
		}
		
                if (msg->type == XSP_MSG_SESS_NACK) {
                        fprintf(stderr, "xsp_signal_path(): could not setup path, error received: %s\n", (char *) msg->msg_body);
			goto error_exit;
                } else if (msg->type != XSP_MSG_SESS_ACK) {
                        d_printf("xsp_signal_path(): error: did not receive a path sess ACK\n");
			goto error_exit;
                }

		if (msg)
			xsp_free_msg(msg);
		free(path);
	}
	else {
		fprintf(stderr, "xsp_signal_path(): error: XSP_CIRCUIT=%s is not a valid path type\n", path_type);
		goto error_exit;
	}

	return 0;

 error_exit:
	return -1;
}		

// FIXME: this won't work as we don't actually have a socket yet...
int xsp_setsockopt(libxspSess *sess, int level, int optname, const void *optval, SOCKLEN_T optlen) {
	int retval = -1;

	switch(optname) {
		case SO_DEBUG:
			d_printf("xsp_setsockopt(): the program is setting the debug flag\n");
			retval = 0;
			sess->debug = 1;
			break;
	}

	// TCP_MAXSEG, 
	if (level == IPPROTO_TCP) {
		switch(optname) {
			case TCP_NODELAY:
				d_printf("xsp_setsockopt(): the program is setting the nodelay flag\n");
				retval = 0;
				sess->nodelay = 1;
				break;
			
			case TCP_MAXSEG:
				d_printf("xsp_setsockopt(): the program is setting the MTU to %d\n", *(int *) optval);
				if (optlen >= sizeof(int)) {
					if (!sess->connected) {
						retval = 0;
						sess->mtu = *(int *)optval;
					} else {
						d_printf("xsp_setsockopt(): can't set MTU: session is already connected\n");
					}
				} else {
					d_printf("xsp_setsockopt(): can't set MTU: argument is smaller than an int\n");
				}
				break;
		}
	} else if (level == XSP_SOCKET || level == SOL_SOCKET) {
		switch(optname) {
			case SO_DEBUG:
				d_printf("xsp_setsockopt(): the program is setting the debug flag\n");
				retval = 0;
				sess->debug = 1;
				break;

			case SO_REUSEADDR:
				d_printf("xsp_setsockopt(): the program is setting the reuseaddr flag\n");
				retval = 0;
				sess->reuseaddr = 1;
				break;

			case SO_RCVTIMEO:
				if (optlen >= sizeof(int)) {
					retval = 0;
					sess->recv_timeout = *(int *)optval;

					if (sess->connected) {
						int new_val;
						SOCKLEN_T new_size = sizeof(new_val);

						std_setsockopt(sess->sock, SOL_SOCKET, SO_RCVTIMEO, &(sess->recv_timeout), sizeof(sess->recv_timeout));

						if (std_getsockopt(sess->sock, SOL_SOCKET, SO_RCVTIMEO, &new_val, &new_size) == 0) {
							sess->recv_timeout = new_val;
						}
					}
				} else {
					d_printf("xsp_setsockopt(): can't set send timeout: argument is smaller than an int\n");
				}
				break;

			case SO_SNDTIMEO:
				if (optlen >= sizeof(int)) {
					retval = 0;
					sess->send_timeout = *(int *)optval;

					if (sess->connected) {
						int new_val;
						SOCKLEN_T new_size = sizeof(new_val);

						std_setsockopt(sess->sock, SOL_SOCKET, SO_SNDTIMEO, &(sess->send_timeout), sizeof(sess->send_timeout));

						if (std_getsockopt(sess->sock, SOL_SOCKET, SO_SNDTIMEO, &new_val, &new_size) == 0) {
							sess->send_timeout = new_val;
						}
					}
				} else {
					d_printf("xsp_setsockopt(): can't set send timeout: argument is smaller than an int\n");
				}
				break;

			case SO_SNDBUF:
				if (optlen >= sizeof(int)) {
					if (!sess->connected) {
						retval = 0;
						sess->send_bufsize = *(int *)optval;
					} else {
						d_printf("xsp_setsockopt(): can't set send buf: session is already connected\n");
					}
				} else {
					d_printf("xsp_setsockopt(): can't set send buf: argument is smaller than an int\n");
				}
				break;

			case SO_RCVBUF:
				if (optlen >= sizeof(int)) {
					if (!sess->connected) {
						retval = 0;
						sess->recv_bufsize = *(int *)optval;
					} else {
						d_printf("xsp_setsockopt(): can't set recv buf: session is already connected\n");
					}
				} else {
					d_printf("xsp_setsockopt(): can't set recv buf: argument is smaller than an int\n");
				}
				break;

			default:
				if (level == SOL_SOCKET && sess->connected) {
					retval = std_setsockopt(sess->sock, level, optname, optval, optlen);
				}
				break;
		}
	} else {
		retval = std_setsockopt(sess->sock, level, optname, optval, optlen);
	}

	return retval;
}

int xsp_getsockopt(libxspSess *sess, int level, int optname, void *optval, SOCKLEN_T *optlen) {
	int retval;

	if (level == XSP_SOCKET) {
		if (*optlen < sizeof(int)) {
			errno = EINVAL;
			d_printf("xsp_getsockopt(): requested a value and didn't give a large enough size\n");
			return -1;
		}

		switch(optname) {
			case SO_RCVTIMEO:
				retval = 0;
				*((int *)optval) = sess->recv_timeout;
				*optlen = sizeof(sess->recv_timeout);
				break;

			case SO_SNDTIMEO:
				retval = 0;
				*((int *)optval) = sess->send_timeout;
				*optlen = sizeof(sess->send_timeout);
				break;

			case SO_SNDBUF:
				retval = 0;
				*((int *)optval) = sess->send_bufsize;
				*optlen = sizeof(sess->send_bufsize);
				break;

			case SO_RCVBUF:
				retval = 0;
				*((int *)optval) = sess->recv_bufsize;
				*optlen = sizeof(sess->recv_bufsize);
				break;

			default:
				errno = ENOPROTOOPT;
				retval = -1;
		}
	} else if (sess->connected) {
		retval = std_getsockopt(sess->sock, level, optname, optval, optlen);
	} else {
		d_printf("xsp_getsockopt(): bad file descriptor\n");
		errno = EBADF;
		return -1;
	}

	return retval;
}

int xsp_bind(){
	return 0;
}

int xsp_accept() {
	return 0;
}

int xsp_close(libxspSess *sess) {

	if (sess->data_connected)
		std_close(sess->data_sock);
	
	if (sess->connected)
		std_close(sess->sock);
	//xsp_free_sess(sess);
	free(sess);

	return 0;
}

int xsp_close2(libxspSess *sess) {

	if (sess->connected) {
		if (xsp_put_msg(sess, 0, XSP_MSG_SESS_CLOSE, sess->sess_id, NULL) < 0) {
			d_printf("xsp_close(): error: failed to send session close message\n");
			return -1;
		}
		std_close(sess->sock);
	}
	
	if (sess->data_connected)
		std_close(sess->data_sock);
		
	free(sess);

	return 0;
}

xspMsg *xsp_get_msg(libxspSess *sess, unsigned int flags) {
	char hdr_buf[32];
	char *buf = NULL;
	int amt_read, rd, remainder;
	xspMsg *msg;
	xspMsgHdr *hdr;

	// if they don't want to wait, check to see if everything can be read in without waiting
	// if not, return an error stating as such
	if (flags & XSP_MSG_NOWAIT) {

		// read in the buffer using MSG_PEEK so as to not actually remove the data from the stream
		rd = recv(sess->sock, hdr_buf, sizeof(xspMsgHdr), MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT);
		if (rd < sizeof(xspMsgHdr)) {
			errno = EAGAIN;
			return NULL;
		}

		hdr = (xspMsgHdr *) hdr_buf;

		// grab the remainder
		remainder = ntohs(hdr->length);
		if (remainder < 0 || remainder > XSP_MAX_LENGTH)
			return NULL;

		// if there is a remainder, allocate a buffer and try to read into that
		if (remainder > 0) {
			buf = (char *) malloc(sizeof(char) * (remainder + sizeof(xspMsgHdr)));
			if (!buf) {
				errno = ENOMEM;
				return NULL;
			}

			rd = recv(sess->sock, buf, sizeof(xspMsgHdr) + remainder, MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT);
			if (rd < (sizeof(xspMsgHdr) + remainder)) {
				free(buf);
				errno = EAGAIN;
				return NULL;
			}

			free(buf);
		}
	}

	// read the header in
	amt_read = recv(sess->sock, hdr_buf, sizeof(xspMsgHdr), MSG_WAITALL);
	if (amt_read < sizeof(xspMsgHdr)) {
		goto error_exit;
	}

	hdr = (xspMsgHdr *) hdr_buf;

	// obtain the length of the message and verify that it fits in bounds
	remainder = ntohs(hdr->length);
	if (remainder < 0 || remainder > XSP_MAX_LENGTH)
		goto error_exit;

	if (remainder > 0) {
		// allocate space for the remainder
		buf = (char *) malloc(sizeof(char) * remainder);
		if (!buf)
			goto error_exit;

		// grab the remainder
		amt_read = recv(sess->sock, buf, remainder, MSG_WAITALL);
		if (amt_read < remainder)
			goto error_exit2;
	}

	// allocate a message to return
	msg = (xspMsg *) malloc(sizeof(xspMsg));
	if (!msg)
		return NULL;

	// fill in the message
	msg->type = hdr->type;
	msg->version = hdr->version;

	bin2hex(hdr->sess_id, msg->sess_id, XSP_SESSIONID_LEN);

	// fill in the message body
	if (xsp_parse_msgbody(msg, buf, remainder, &(msg->msg_body)) != 0)
		goto error_exit3;

	if (buf)
		free(buf);

	return msg;

error_exit3:
	free(msg);
error_exit2:
	free(buf);
error_exit:
	return NULL;
}

int xsp_put_msg(libxspSess *sess, uint8_t version, uint8_t type, char *sess_id, void *msg_body) {
	char *msg_buf;
	int msg_buf_len;
	int amt_sent;
	int sent;
	int msg_len;
	xspMsg msg;

	msg_buf = (char *) malloc(sizeof(char) * 65536);
	if (!msg_buf)
		return -1;

	msg_buf_len = 65536;

	msg.version = version;
	msg.type = type;
	msg.msg_body = msg_body;
	memcpy(msg.sess_id, sess_id, 2*XSP_SESSIONID_LEN+1);

	msg_len = xsp_writeout_msg(msg_buf, msg_buf_len, version, type, (void*)&msg, msg_body);

	if (msg_len < 0)
		goto write_error;

	amt_sent = 0;
	do {
		sent = send(sess->sock, msg_buf + amt_sent, msg_len - amt_sent, 0);
		if (sent <= 0)
			goto write_error;

		amt_sent += sent;
	} while (amt_sent < msg_len);

	free(msg_buf);

	return msg_len;

write_error:
	free(msg_buf);

	return -1;
}

ssize_t xsp_recv(libxspSess *sess, void *buf, size_t len, int flags) {

	if (!sess->connected) {
		errno = ENOTCONN;
		return -1;
	}

	return std_recv(sess->sock, buf, len, flags);
}

ssize_t xsp_send(libxspSess *sess, const void *buf, size_t len, int flags) {

	if (!sess->connected) {
		errno = ENOTCONN;
		return -1;
	}

	return std_send(sess->sock, buf, len, flags);
}

int xsp_shutdown(libxspSess *sess, int how) {
	if (!sess->connected) {
		errno = ENOTCONN;
		return -1;
	}

	return std_shutdown(sess->sock, how);
}

int xsp_set_session_socket(libxspSess *sess, int new_sd) {
	if (sess->connected) {
		sess->sock = new_sd;
		return 0;
	} else {
		return -1;
	}
}

int xsp_get_session_socket(libxspSess *sess) {
	if (sess->connected) {
		return sess->sock;
	} else {
		return -1;
	}
}

// since we can externally set the session socket,
// allow session to be "connected" as well
int xsp_set_session_connected(libxspSess *sess) {
	sess->connected = 1;
	return 0;
}

int xsp_send_ping(libxspSess *sess) {
	if (xsp_put_msg(sess, 0, XSP_MSG_PING, sess->sess_id, NULL) < 0) {
		d_printf("xsp_ping(): error: failed to send ping message\n");
		return -1;
	}
	return 0;
}

int xsp_recv_ping(libxspSess *sess) {
	xspMsg *msg;
	
	msg = xsp_get_msg(sess, 0);
	if (!msg) {
		d_printf("xsp_ping(): error: did not receive a valid rxsponse\n");
		return -1;
	}

	if (msg->type == XSP_MSG_PONG) {
		d_printf("xsp_recv_ping(): PONG\n");
		return 0;
	}
	else {
		d_printf("xsp_ping(): invalid message type\n");
		return -1;
	}
}
		
static int xsp_hash_password(const unsigned char *pass, unsigned int pass_len, const unsigned char *nonce, unsigned char *ret_hash) {
	unsigned char buf[SHA_DIGEST_LENGTH];
	int i;

	SHA1(pass, pass_len, buf);

	for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
		buf[i] ^= nonce[i];
	}

	SHA1(buf, SHA_DIGEST_LENGTH, ret_hash);

	return 0;
}
