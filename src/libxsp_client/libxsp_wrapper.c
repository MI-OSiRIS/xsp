#include "config.h"

#include "libxsp_client_private.h"

#include "xsp.h"

#include <sys/queue.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/ip.h>

static int (*std_socket)(int, int, int);
static int (*std_connect)(int, const struct sockaddr *, SOCKLEN_T); 
static int (*std_setsockopt)(int, int, int, const void *, SOCKLEN_T);
static int (*std_getsockopt)(int, int, int, void *, SOCKLEN_T *); 
static int (*std_close)(int);
static ssize_t (*std_send)(int, const void *, size_t, int);
static ssize_t (*std_recv)(int, void *, size_t, int);
static int (*std_shutdown)(int, int);
static ssize_t (*std_read)(int fd, void *buf, size_t count);
static ssize_t (*std_write)(int fd, const void *buf, size_t count);

int libxsp_wrapper_status = -1;

static LIST_HEAD(listhead, libxsp_sess_info_t) sess_list;
static pthread_mutex_t sess_list_lock;

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

void libxsp_wrapper_init() {
	void *handle;
	const char *error;
	int res;

	d_printf("libxsp_wrapper_init\n");

	if (libxsp_init() < 0)
		goto error_exit;

	// open up the standard library
	handle = dlopen("/lib/libc.so.6", RTLD_LAZY);
	if (!handle) {
		d_printf("xsp_init_wrapper(): couldn't load libc: %s\n", dlerror());
		goto error_exit;
	}

	// find the socket symbol
	std_socket = (int (*)(int, int, int)) dlsym(handle, "socket");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading socket symbol: %s\n", error);
		goto error_exit2;
	}

	// find the connect symbol
	std_connect = (int (*)(int, const struct sockaddr *, SOCKLEN_T)) dlsym(handle, "connect");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading connect symbol: %s\n", error);
		goto error_exit2;
	}

	// find the setsockopt symbol
	std_setsockopt = (int (*)(int, int, int, const void *, SOCKLEN_T)) dlsym(handle, "setsockopt");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading setsockopt symbol: %s\n", error);
		goto error_exit2;
	}

	// find the getsockopt symbol
	std_getsockopt = (int (*)(int, int, int, void *, SOCKLEN_T *)) dlsym(handle, "getsockopt");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading getsockopt symbol: %s\n", error);
		goto error_exit2;
	}

	std_close = (int (*)(int)) dlsym(handle, "close");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_shutdown = (int (*)(int,int)) dlsym(handle, "shutdown");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_send = (ssize_t (*)(int,const void *,size_t,int)) dlsym(handle, "send");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_recv = (ssize_t (*)(int,void *,size_t,int)) dlsym(handle, "recv");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_write = dlsym(handle, "write");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	std_read = dlsym(handle, "read");
	if ((error = dlerror()) != NULL) {
		d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
		goto error_exit2;
	}

	res = pthread_mutex_init(&sess_list_lock, NULL);
	if (res != 0)
		goto error_exit;

	LIST_INIT(&sess_list);

	libxsp_wrapper_status = 0;

	return;

error_exit2:
	dlclose(handle);
error_exit:
	return;
}

int xsp_add_sess(int s, libxspSess *sess) {

	sess->sock_desc = s;

	pthread_mutex_lock(&sess_list_lock);
	{
		LIST_INSERT_HEAD(&sess_list, sess, sessions);
	}
	pthread_mutex_unlock(&sess_list_lock);

	return 0;
}

int xsp_del_sess(libxspSess *sess) {

	pthread_mutex_lock(&sess_list_lock);
	{
		LIST_REMOVE(sess, sessions);
	}
	pthread_mutex_unlock(&sess_list_lock);

	return 0;
}

libxspSess *xsp_find_sess(int s) {
	libxspSess *curr, *ret_info;

	ret_info = NULL;

	d_printf("Finding %d\n", s);

	pthread_mutex_lock(&sess_list_lock);
	{
		for(curr = sess_list.lh_first; curr != NULL; curr = curr->sessions.le_next) {
			if (curr->sock_desc == s) {
				ret_info = curr;
				break;
			}
		}
	}
	pthread_mutex_unlock(&sess_list_lock);

	return ret_info;
}

// wrapper for the socket function
int socket(int domain, int type, int protocol) {
	libxspSess *new_sess;
	int new_socket;

	d_printf("socket\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (domain == AF_XSP || (domain == AF_INET && type == SOCK_STREAM)) {

		new_sess = xsp_session();
		if (!new_sess) {
			d_printf("xsp_socket(): failed to allocate session: %s\n", strerror(errno));
			errno = ENOMEM;
			goto error_exit;
		}

		new_socket = std_socket(AF_INET, SOCK_STREAM, 0);
		if (new_socket < 0) {
			d_printf("xsp_socket(): failed to obtain socket: %s\n", strerror(errno));
			goto error_exit2;
		}

		if (xsp_add_sess(new_socket, new_sess)) {
			d_printf("xsp_socket(): failed to add session to session list: %s\n", strerror(errno));
			errno = ENOMEM;
			goto error_exit2;
		}
	} else {
		new_socket = std_socket(domain,type,protocol);
	}

	return new_socket;
	
error_exit2:
	free(new_sess);
error_exit:
	return -1;
}

// wrapper for the connect function
int connect(int sockfd, const struct sockaddr *serv_addr, SOCKLEN_T addrlen) {
	libxspSess *sess;
	int tos_bits;
	SOCKLEN_T tos_bits_length = sizeof(tos_bits);
	int retval;
	char dest[XSP_HOPID_LEN];

	d_printf("connect\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		goto error_exit;
	}

	if (getsockopt(sockfd, IPPROTO_IP, IP_TOS, (char *) &tos_bits, &tos_bits_length) < 0) {
		d_printf("getsockopt failed: %s\n", strerror(errno));
		tos_bits = -1;
	}

	sess = xsp_find_sess(sockfd);
	if (!sess || tos_bits == -1 || tos_bits & IPTOS_LOWDELAY || tos_bits & IPTOS_MINCOST) {
		d_printf("doing a std connect, our session handling is no longer applicable\n");
		if (sess)
			xsp_del_sess(sess);
		return std_connect(sockfd, serv_addr, addrlen);
	}

	xsp_sa2hopid_r(serv_addr, addrlen, dest, sizeof(dest), 0);

	xsp_sess_appendchild(sess, dest, 0);

	d_printf("Connecting to: %s\n", dest);

	retval = xsp_connect(sess);

	d_printf("done connect\n");

	return retval;

error_exit:
	return -1;
}

#if 0 // SOLARIS
// wrapper for Solaris' getsockopt function
int getsockopt(int s, int level, int optname, void *optval, Psocklen_t optlen) {
	libxspSess *sess;

	d_printf("getsockopt\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		goto error_exit;
	}

	sess = xsp_find_sess(sockfd);
	if (!sess) {
		return std_getsockopt(s, level, optname, optval, optlen);
	}

	if (level != AF_XSP) {
		return std_getsockopt(sess, level, optname, optval, optlen);
	} else {
		return xsp_getsockopt(sess, level, optname, optval, optlen);
	}
}
#else
// wrapper for everyone else's getsockopt function
int getsockopt(int s, int level, int optname, void *optval, SOCKLEN_T *optlen) {
	libxspSess *sess;

	d_printf("getsockopt\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		return -1;
	}

	sess = xsp_find_sess(s);
	if (!sess) {
		d_printf("std_getsockopt\n");
		return std_getsockopt(s, level, optname, optval, optlen);
	}

	if (level != AF_XSP) {
		d_printf("std_getsockopt\n");
		return std_getsockopt(s, level, optname, optval, optlen);
	} else {
		d_printf("xsp_getsockopt\n");
		return xsp_getsockopt(sess, level, optname, optval, optlen);
	}
}
#endif

// wrapper for setsockopt function
int
setsockopt(int s, int level, int optname, const void *optval, SOCKLEN_T optlen) {
	libxspSess *sess;

	d_printf("setsockopt\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		return -1;
	}

	sess = xsp_find_sess(s);
	if (!sess) {
		return std_setsockopt(s, level, optname, optval, optlen);
	}

	return xsp_setsockopt(sess, level, optname, optval, optlen);
}

// wrapper for close function
int close(int fd) {
	libxspSess *sess;

	d_printf("close\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		return -1;
	}

	sess = xsp_find_sess(fd);
	if (!sess) {
		return std_close(fd);
	}

	xsp_del_sess(sess);

	return xsp_close(sess);
}

ssize_t recv(int s, void *buf, size_t len, int flags) {
	libxspSess *sess;

	d_printf("recv\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		return -1;
	}

	sess = xsp_find_sess(s);
	if (!sess) {
		return std_recv(s, buf, len, flags);
	}

	return xsp_recv(sess, buf, len, flags);
}

ssize_t send(int s, const void *buf, size_t len, int flags) {
	libxspSess *sess;

	d_printf("send\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		return -1;
	}

	sess = xsp_find_sess(s);
	if (!sess) {
		return std_send(s, buf, len, flags);
	}

	return xsp_send(sess, buf, len, flags);
}

ssize_t read(int fd, void *buf, size_t count) {
	libxspSess *sess;

	d_printf("read\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		return -1;
	}

	sess = xsp_find_sess(fd);
	if (!sess) {
		return std_read(fd, buf, count);
	}

	d_printf("done read\n");
	return xsp_recv(sess, buf, count, 0);
}

ssize_t write(int fd, const void *buf, size_t count) {
	libxspSess *sess;

	d_printf("write\n");

	pthread_once(&init_once, libxsp_wrapper_init);

	if (libxsp_wrapper_status != 0) {
		errno = ENOMEM;
		return -1;
	}

	sess = xsp_find_sess(fd);
	if (!sess) {
		return std_write(fd, buf, count);
	}

	return xsp_send(sess, buf, count, 0);
}
