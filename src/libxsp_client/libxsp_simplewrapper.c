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
#include "config.h"

#include "libxsp_client_private.h"
#include "libxsp_wrapper_route.h"

#include "xsp.h"
#include "compat.h"

#include <sys/queue.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/ip.h>

#ifdef NETLOGGER
#include "nl.h"
#include "nltransfer.h"
#include "nlsumm.h"

#define NL_LVL_UDEF NL_LVL_DEBUG
#endif

#ifdef DEBUG
#define d_printf(fmt, args...) fprintf(output, "XSP:"fmt, ##args)
#else
#define d_printf(fmt, args...)
#endif

FILE *output;

static int (*std_socket)(int, int, int);
static int (*std_connect)(int, const struct sockaddr *, SOCKLEN_T);
static int (*std_setsockopt)(int, int, int, const void *, SOCKLEN_T);
static int (*std_getsockopt)(int, int, int, void *, SOCKLEN_T *);
static int (*std_getpeername)(int s, struct sockaddr *name, SOCKLEN_T *namelen);
static int (*std_close)(int);
static ssize_t (*std_send)(int, const void *, size_t, int);
static ssize_t (*std_recv)(int, void *, size_t, int);
static int (*std_shutdown)(int, int);
static ssize_t (*std_read)(int fd, void *buf, size_t count);
static ssize_t (*std_write)(int fd, const void *buf, size_t count);

#ifdef NETLOGGER
static int (*std_accept)(int, struct sockaddr *, SOCKLEN_T *);
#endif

int libxsp_wrapper_status = -1;

static LIST_HEAD(listhead, libxsp_sess_info_t) sess_list;
static pthread_mutex_t sess_list_lock;

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

#ifdef NETLOGGER
NL_log_T nllog;
NL_summ_T prog_summ, int_summ;
libxspSess *sock_fds[MAX_FD];
int stream_ids[MAX_FD];

int get_next_stream_id() {
  int i;
  for (i=1; i<MAX_FD; i++)
    if (stream_ids[i] == 0) {
      stream_ids[i] = 1;
      return i;
    }
  d_printf("Ran out of stream_ids for NetLogger!\n");
  return 0;
}
#endif

void libxsp_wrapper_init() {
  void *handle;
  const char *error;
  int res;

  if (getenv("XSP_OUTPUT_FILE") != NULL) {
    output = fopen(getenv("XSP_OUTPUT_FILE"), "w");
  }

  if (output == NULL) {
    output = stdout;
  }

  d_printf("libxsp_wrapper_init(): initializing xsp wrapper\n");

  if (libxsp_init() < 0) {
    d_printf("xsp_init_wrapper(): failed to initialize XSP protocol handler\n");
    goto error_exit;
  }

  if (libxsp_wrapper_route_init() < 0) {
    d_printf("xsp_init_wrapper(): failed to initialize route handler\n");
    goto error_exit;
  }

  if (getenv("XSP_ROUTE_FILE") != NULL) {
    d_printf("libxsp_wrapper_init(): reading route file: \"%s\"\n", getenv("XSP_ROUTE_FILE"));
    if (libxsp_wrapper_route_read(getenv("XSP_ROUTE_FILE")) < 0) {
      d_printf("xsp_init_wrapper(): failed to load route file: \"%s\"\n", getenv("XSP_ROUTE_FILE"));
      goto error_exit;
    }
  }

#ifdef __APPLE__
  // open up the standard library
  handle = dlopen("libgcc_s.1.dylib", RTLD_LAZY);
  if (!handle) {
    d_printf("libxsp_init(): couldn't load libgc: %s\n", dlerror());
    goto error_exit2;
  }
#else
  // open up the standard library
  handle = dlopen("libc.so.6", RTLD_LAZY);
  if (!handle) {
    handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
      d_printf("xsp_init_wrapper(): couldn't load libc: %s\n", dlerror());
      goto error_exit2;
    }
  }
#endif
  // find the socket symbol
  std_socket = (int (*)(int, int, int)) dlsym(handle, "socket");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading socket symbol: %s\n", error);
    goto error_exit3;
  }

#ifdef NETLOGGER
  // find the accept symbol
  std_accept = (int (*)(int, struct sockaddr *, SOCKLEN_T *)) dlsym(handle, "accept");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading connect symbol: %s\n", error);
    goto error_exit3;
  }
#endif

  // find the connect symbol
  std_connect = (int (*)(int, const struct sockaddr *, SOCKLEN_T)) dlsym(handle, "connect");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading connect symbol: %s\n", error);
    goto error_exit3;
  }

  // find the setsockopt symbol
  std_setsockopt = (int (*)(int, int, int, const void *, SOCKLEN_T)) dlsym(handle, "setsockopt");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading setsockopt symbol: %s\n", error);
    goto error_exit3;
  }

  // find the getsockopt symbol
  std_getsockopt = (int (*)(int, int, int, void *, SOCKLEN_T *)) dlsym(handle, "getsockopt");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading getsockopt symbol: %s\n", error);
    goto error_exit3;
  }

  std_close = (int (*)(int)) dlsym(handle, "close");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
    goto error_exit3;
  }

  std_shutdown = (int (*)(int,int)) dlsym(handle, "shutdown");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
    goto error_exit3;
  }

  std_getpeername = (ssize_t (*)(int,const void *,size_t,int)) dlsym(handle, "getpeername");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
    goto error_exit3;
  }

  std_send = (ssize_t (*)(int,const void *,size_t,int)) dlsym(handle, "send");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
    goto error_exit3;
  }

  std_recv = (ssize_t (*)(int,void *,size_t,int)) dlsym(handle, "recv");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
    goto error_exit3;
  }

  std_write = dlsym(handle, "write");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
    goto error_exit3;
  }

  std_read = dlsym(handle, "read");
  if ((error = dlerror()) != NULL) {
    d_printf("xsp_init_wrapper(): error loading close symbol: %s\n", error);
    goto error_exit3;
  }

  res = pthread_mutex_init(&sess_list_lock, NULL);
  if (res != 0) {
    d_printf("xsp_init_wrapper(): error initializing session list mutex: %s\n", strerror(errno));
    goto error_exit3;
  }

  LIST_INIT(&sess_list);

  libxsp_wrapper_status = 0;

#ifdef NETLOGGER
  int i;
  for (i=0; i<MAX_FD; i++) {
    sock_fds[i] = NULL;
    stream_ids[i] = 0;
  }

  /* open NetLogger handle, nllog is global */
  nllog = NL_open(NULL);
  if (!nllog) {
    d_printf("NETLOGGER: error opening log file\n");
    exit(-1);
  }

  NL_set_level(nllog, NL_LVL_UDEF);

  prog_summ = NL_summ();
  NL_summ_set_shared_output(prog_summ, nllog);
  NL_transfer_init(prog_summ, -1, NL_LVL_UDEF);

  if (getenv("NL_LOG_SUMMARY") == NULL)
    NL_transfer_set_passthrough(prog_summ);

  NL_summ_add_log(prog_summ, nllog);

  //int_summ = NL_summ();
  //NL_summ_set_shared_output(int_summ, nllog);
  //NL_transfer_init(int_summ, 1000000, NL_LVL_UDEF);
  //NL_transfer_set_passthrough(int_summ);
  //NL_summ_add_log(int_summ, nllog);
#endif

  return;

error_exit3:
  dlclose(handle);
error_exit2:
  // shutdown the routing infrastructure
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

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    d_printf("Error: wrapper isn't initialized. Using standard socket calls\n");
    return std_socket(domain,type,protocol);
  }

  if (domain == AF_XSP || (domain == AF_INET && type == SOCK_STREAM)) {
    d_printf("socket(): allocating an xsp session\n");

    new_sess = xsp_session();
    if (!new_sess) {
      d_printf("xsp_socket(): failed to allocate session: %s\n", strerror(errno));
      errno = ENOMEM;
      goto error_exit;
    }
#ifdef NETLOGGER

    new_sess->nl_id = get_next_stream_id();
#endif
    new_socket = std_socket(AF_INET, SOCK_STREAM, 0);
    if (new_socket < 0) {
      d_printf("xsp_socket(): failed to obtain socket: %s\n", strerror(errno));
      errno = ENOMEM;
      goto error_exit2;
    }

    if (xsp_add_sess(new_socket, new_sess)) {
      d_printf("xsp_socket(): failed to add session to session list: %s\n", strerror(errno));
      errno = ENOMEM;
      goto error_exit2;
    }

    d_printf("socket(): session id for %d is: \"%s\"\n", new_socket, new_sess->sess_id);
  }
  else {
    d_printf("socket(): requested a socket that isn't compatible with xsp\n");
    new_socket = std_socket(domain,type,protocol);
  }

  d_printf("socket(): %d\n", new_socket);

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
  int new_sock;
  const struct libxsp_route_path_info *pi;
  char **path = NULL;
  int path_count = 0;
  int i;
  char *tmp_hop[1];
  int free_path = 0;
  char *xsp_sec;
  char *xsp_net_path;

  pthread_once(&init_once, libxsp_wrapper_init);

  d_printf("connect(%d)\n", sockfd);

  if (libxsp_wrapper_status != 0) {
    return std_connect(sockfd, serv_addr, addrlen);
  }

  if (getsockopt(sockfd, IPPROTO_IP, IP_TOS, (char *) &tos_bits, &tos_bits_length) < 0) {
    d_printf("Error: getsockopt failed. Reverting to standard TCP connection: %s\n", strerror(errno));
//	} else if (tos_bits & IPTOS_LOWDELAY || tos_bits & IPTOS_MINCOST) {
//		d_printf("connect(): socket specified as lowdelay or mincost\n");
  }
  else if (serv_addr->sa_family == AF_INET || serv_addr->sa_family == AF_INET6) {
    d_printf("connect(): looking up route\n");

    pi = libxsp_wrapper_route_lookup_sa(serv_addr);

    if (!pi) {
      d_printf("connect(): no route found\n");
    }

    if (pi && pi->port_count > 0) {
      int i;

      for(i = 0; i < pi->port_count; i++) {
        if (serv_addr->sa_family == AF_INET) {
          if (pi->ports[i] == ntohs(((struct sockaddr_in *)serv_addr)->sin_port)) {
            d_printf("connect(): found corresponding route for the specified port %d\n", ntohs(((struct sockaddr_in *)serv_addr)->sin_port));
            path = pi->path;
            path_count = pi->path_count;
            break;
          }
        }
        else {
          //if (pi->ports[i] == ((struct sockaddr6_in *)serv_addr)->sin6_port)
          //	break;
        }
      }

      if (path == NULL) {
        d_printf("connect(): path information was found, but no matching port\n");
      }


    }
    else if (pi && pi->port_count == 0) {
      d_printf("connect(): found corresponding route\n");
      path = pi->path;
      path_count = pi->path_count;
    }
    else if (getenv("XSP_PATH") != NULL) {
      d_printf("connect(): using the path specified in environmental variable XSP_PATH: \"%s\"\n", getenv("XSP_PATH"));
      path = split(getenv("XSP_PATH"), ",", &path_count);
      if (!path) {
        d_printf("connect(): parsing of variable XSP_PATH failed. it needs to be a comma separated list of hop ids\n");
        path_count = 0;
      }
      else {
        free_path = 1;
      }
    }
    else if (getenv("XSP_HOP") != NULL) {
      d_printf("connect(): using the hop specified in environmental variable XSP_HOP: \"%s\"\n", getenv("XSP_HOP"));
      tmp_hop[0] = getenv("XSP_HOP");
      path = tmp_hop;
      path_count = 1;
    }
  }

  if (path_count == 0) {
    d_printf("connect(): no xsp path specified\n");
  }

  sess = xsp_find_sess(sockfd);
  if (!sess || path_count == 0) {
    if (sess) {
      d_printf("connect(): initialized allocated session \"%s\", but on connect, xsp should not be used\n", sess->sess_id);
      xsp_del_sess(sess);
    }
    return std_connect(sockfd, serv_addr, addrlen);
  }

  for(i = 0; i < path_count; i++) {
    d_printf("connect(): adding \"%s\" to the path\n", path[i]);
    xsp_sess_appendchild(sess, path[i], XSP_HOP_NATIVE);
  }

  if (free_path) {
    for(i = 0; i < path_count; i++)
      free(path[i]);
    free(path);
  }

  xsp_sa2hopid_r(serv_addr, addrlen, dest, sizeof(dest), 0);

  d_printf("connect(): adding \"%s\" to the path\n", dest);

  xsp_sess_appendchild(sess, dest, 0);

  xsp_sec = getenv("XSP_SEC");
  if (xsp_sec) {
    if (!strcasecmp(xsp_sec, "ssh"))
      xsp_sess_set_security(sess, NULL, XSP_SEC_SSH);
    else if (!strcasecmp(xsp_sec, "ssl"))
      xsp_sess_set_security(sess, NULL, XSP_SEC_SSL);
    else
      xsp_sess_set_security(sess, NULL, XSP_SEC_NONE);
  }

  if ((retval = xsp_connect(sess)) != 0) {
    fprintf(stderr, "XSP: connect(): failed to complete session with %s\n",
            xsp_hop_getid(sess->child[0]));
    return retval;
  }

  xsp_net_path = getenv("XSP_NET_PATH");
  if (xsp_net_path) {
    d_printf("XSP: connect(): found XSP_NET_PATH, TYPE: %s, ACTION: CREATE\n", xsp_net_path);
    if (xsp_signal_path(sess, NULL) != 0) {
      fprintf(stderr, "XSP: connect(): failed to complete network path setup\n");
    }
  }

  // just do a regular connect now that the session is configured
  return std_connect(sockfd, serv_addr, addrlen);
}

#if 0 // SOLARIS
// wrapper for Solaris' getsockopt function
int getsockopt(int s, int level, int optname, void *optval, Psocklen_t optlen) {
  libxspSess *sess;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    return std_getsockopt(s, level, optname, optval, optlen);
  }

  sess = xsp_find_sess(sockfd);
  if (!sess) {
    return std_getsockopt(s, level, optname, optval, optlen);
  }

  if (level != AF_XSP) {
    return std_getsockopt(sess, level, optname, optval, optlen);
  }
  else {
    return xsp_getsockopt(sess, level, optname, optval, optlen);
  }
}
#else
// wrapper for everyone else's getsockopt function
int getsockopt(int s, int level, int optname, void *optval, SOCKLEN_T *optlen) {
  libxspSess *sess;

  pthread_once(&init_once, libxsp_wrapper_init);

  d_printf("getsockopt(%d, %d, %d)\n", s, level, optname);

  if (libxsp_wrapper_status != 0) {
    return std_getsockopt(s, level, optname, optval, optlen);
  }

  sess = xsp_find_sess(s);
  if (!sess) {
    return std_getsockopt(s, level, optname, optval, optlen);
  }

  if (level != AF_XSP) {
    return std_getsockopt(s, level, optname, optval, optlen);
  }
  else {
    return xsp_getsockopt(sess, level, optname, optval, optlen);
  }
}
#endif

int getpeername(int s, struct sockaddr *name, SOCKLEN_T *namelen) {
  libxspSess *sess;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    return std_getpeername(s, name, namelen);
  }

  d_printf("getpeername(%d)\n", s);

  sess = xsp_find_sess(s);
  if (!sess) {
    return std_getpeername(s, name, namelen);
  }

  if (!sess->connected) {
    errno = ENOTCONN;
    goto error_exit;
  }

  if (*namelen < sess->end_host_addrlen) {
    errno = ENOBUFS;
    goto error_exit;
  }

  *name = sess->end_host_addr;
  *namelen = sess->end_host_addrlen;

  return 0;

error_exit:
  return -1;
}

// wrapper for setsockopt function
int setsockopt(int s, int level, int optname, const void *optval, SOCKLEN_T optlen) {
  libxspSess *sess;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    return std_setsockopt(s, level, optname, optval, optlen);
  }

  sess = xsp_find_sess(s);
  if (!sess) {
    return std_setsockopt(s, level, optname, optval, optlen);
  }

  d_printf("setsockopt(%d, %d, %d)\n", s, level, optname);

  std_setsockopt(s, level, optname, optval, optlen);

  return xsp_setsockopt(sess, level, optname, optval, optlen);
}

// wrapper for close function
int close(int fd) {
  libxspSess *sess;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    return std_close(fd);
  }

  sess = xsp_find_sess(fd);

#ifdef NETLOGGER
  if (sess || (sock_fds[fd] != NULL))
    NL_transfer_finalize(prog_summ);
#endif

  if (!sess) {
    return std_close(fd);
  }

  xsp_del_sess(sess);

#ifdef NETLOGGER
  stream_ids[sess->nl_id] = 0;
#endif

  return xsp_close2(sess);
}

#ifdef DEBUG
ssize_t recv(int s, void *buf, size_t len, int flags) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(s);

  if (!sess) {
    return std_recv(s, buf, len, flags);
  }

  n = std_recv(s, buf, len, flags);

  return n;
}

ssize_t send(int s, const void *buf, size_t len, int flags) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(s);

  if (!sess)
    return std_send(s, buf, len, flags);

  n = std_send(s, buf, len, flags);

  return n;

}

ssize_t read(int fd, void *buf, size_t count) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(fd);

  if (sess == NULL)
    return std_read(fd, buf, count);

  n = std_read(fd, buf, count);

  return n;
}

ssize_t write(int fd, const void *buf, size_t count) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(fd);
  if (sess == NULL)
    return std_write(fd, buf, count);

  n = std_write(fd, buf, count);

  return n;
}

#else
#ifdef NETLOGGER
ssize_t recv(int s, void *buf, size_t len, int flags) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(s);

  if (!sess)
    sess = sock_fds[s];

  if (!sess) {
    return std_recv(s, buf, len, flags);
  }

  NL_transfer_start(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_READ, sess->sess_id, sess->nl_id, sess->block_id);
  n = std_recv(s, buf, len, flags);
  NL_transfer_end(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_READ, sess->sess_id, sess->nl_id, sess->block_id, (double)n);
  sess->block_id++;

  return n;
}


ssize_t send(int s, const void *buf, size_t len, int flags) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(s);

  if (!sess)
    sess = sock_fds[s];

  if (!sess) {
    return std_send(s, buf, len, flags);
  }

  NL_transfer_start(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_WRITE, sess->sess_id, sess->nl_id, sess->block_id);
  n = std_send(s, buf, len, flags);
  NL_transfer_end(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_WRITE, sess->sess_id, sess->nl_id, sess->block_id, (double)n);
  sess->block_id++;

  return n;
}

ssize_t read(int fd, void *buf, size_t count) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(fd);

  if (!sess)
    sess = sock_fds[fd];

  if (!sess) {
    return std_read(fd, buf, count);
  }

  NL_transfer_start(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_READ, sess->sess_id, sess->nl_id, sess->block_id);
  n = std_read(fd, buf, count);
  NL_transfer_end(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_READ, sess->sess_id, sess->nl_id, sess->block_id, (double)n);
  sess->block_id++;

  return n;
}

ssize_t write(int fd, const void *buf, size_t count) {
  libxspSess *sess;
  int n;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(fd);

  if (!sess)
    sess = sock_fds[fd];

  if (!sess) {
    return std_write(fd, buf, count);
  }

  NL_transfer_start(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_WRITE, sess->sess_id, sess->nl_id, sess->block_id);
  n = std_write(fd, buf, count);
  NL_transfer_end(nllog, NL_LVL_UDEF, NL_TRANSFER_NET_WRITE, sess->sess_id, sess->nl_id, sess->block_id, (double)n);
  sess->block_id++;

  return n;
}

// wrapper for the accept function
int accept(int sockfd, struct sockaddr *serv_addr, SOCKLEN_T *addrlen) {
  libxspSess *sess;
  int new_sock;

  pthread_once(&init_once, libxsp_wrapper_init);

  if (libxsp_wrapper_status != 0) {
    errno = ENOMEM;
    return -1;
  }

  sess = xsp_find_sess(sockfd);
  if (!sess) {
    return std_accept(sockfd, serv_addr, addrlen);
  }
  else {
    new_sock = std_accept(sockfd, serv_addr, addrlen);

    if (new_sock < MAX_FD)
      sock_fds[new_sock] = sess;
    else
      d_printf("accept: returned fd out of range [0-%d]...not logging!\n", MAX_FD-1);

    return new_sock;
  }
}
#endif
#endif
