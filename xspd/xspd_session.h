#ifndef XSPD_SESSION_H
#define XSPD_SESSION_H

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <pthread.h>

#include "queue.h"

#include "libxsp.h"
#include "xsp-proto.h"
#include "xspd_settings.h"

typedef struct xspd_session_t {
	char id[2*XSP_SESSIONID_LEN + 1];

#ifdef NETLOGGER
        int nl_id;
#endif

	xspHop **child;
	int child_count;

	char *user;

	xspdSettings *requested_settings;

	xspHop *next_hop_info;

	LIST_HEAD(sess_pc_listhead, xspd_connection_t) parent_conns;
	LIST_HEAD(sess_cc_listhead, xspd_connection_t) child_conns;
	
	LIST_HEAD(sess_pdc_listhead, xspd_connection_t) parent_data_conns;
        LIST_HEAD(sess_cdc_listhead, xspd_connection_t) child_data_conns;

	struct xspd_credentials_t *credentials;

	struct timeval start_time, end_time;

	int references;
	pthread_mutex_t references_lock;

	LIST_ENTRY(xspd_session_t) sess_list;
} xspdSess;

int xspd_sessions_init();

int xspd_setup_session(xspdSess *sess, char ***error_msgs);
void xspd_end_session(xspdSess *sess);
xspdSess *xspd_convert_xspSess(xspSess *old_sess);
xspdSess *xspd_alloc_sess();

xspdSess **xspd_get_sessions(int *count);

inline char *xspd_session_get_id(xspdSess *sess);
inline char *xspd_session_get_user(xspdSess *sess);
inline void xspd_session_set_user(xspdSess *sess, char *user);
inline void xspd_session_close_connections(xspdSess *sess);
void xspd_free_session(xspdSess *sess);
xspdSess *xspd_session_get_ref(xspdSess *sess);
xspdSess *__xspd_session_get_ref(xspdSess *sess);
void xspd_session_put_ref(xspdSess *sess);
int xspd_num_sessions();
void xspd_session_finalize(xspdSess *sess);

int xspd_session_setup_path(xspdSess *sess, const void *msg, char ***error_msgs);
int xspd_session_data_open(xspdSess *sess, const void *msg, char ***error_msgs);

#include "xspd_listener.h"

void *xspd_default_handle_conn(void *arg);

#ifdef NETLOGGER
int get_next_stream_id();
#endif

#endif
