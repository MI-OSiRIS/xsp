#ifndef XSP_SESSION_H
#define XSP_SESSION_H

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <pthread.h>

#include "queue.h"

#include "libxsp.h"
#include "xsp-proto.h"
#include "xsp_settings.h"
#include "xsp_conn.h"

typedef struct common_session_t {
	char id[2*XSP_SESSIONID_LEN + 1];

        struct xsp_addr src_eid;
        struct xsp_addr dst_eid;

	xspHop **child;
	int child_count;
	
	uint8_t version;
	
	char *user;
	
	xspSettings *requested_settings;

	xspHop *next_hop_info;

	LIST_HEAD(sess_pc_listhead, xsp_connection_t) parent_conns;
	LIST_HEAD(sess_cc_listhead, xsp_connection_t) child_conns;
	
	LIST_HEAD(sess_pdc_listhead, xsp_connection_t) parent_data_conns;
        LIST_HEAD(sess_cdc_listhead, xsp_connection_t) child_data_conns;

	int connected;
	int state;
	
	struct xsp_connection_t *cntl_conn;
	struct xsp_credentials_t *credentials;
	
	struct timeval start_time, end_time;
	
	int references;
	pthread_mutex_t references_lock;
	
	void *(*proto_cb) (struct common_session_t *, xspMsg*);

	LIST_ENTRY(common_session_t) sess_list;

#ifdef NETLOGGER
        int nl_id;
#endif
} comSess;

int xsp_sessions_init();

comSess *xsp_wait_for_session(xspConn *conn, comSess **ret_sess, int (*fn) (comSess *));
int xsp_set_proto_cb(comSess *sess, void *(*fn) (comSess *, xspMsg *));
int xsp_proto_loop(comSess *sess);

int xsp_setup_session(comSess *sess, char ***error_msgs);
void xsp_end_session(comSess *sess);
comSess *xsp_convert_xspSess(xspMsg *msg);
comSess *xsp_alloc_com_sess();

comSess **xsp_get_sessions(int *count);
int xsp_session_get_blocks(const xspMsg *msg, int opt_type, xspBlock ***ret_blocks, int *count);

inline char *xsp_session_get_id(comSess *sess);
inline char *xsp_session_get_user(comSess *sess);
inline void xsp_session_set_user(comSess *sess, char *user);
inline void xsp_session_close_connections(comSess *sess);

void xsp_free_session(comSess *sess);
comSess *xsp_session_get_ref(comSess *sess);
comSess *__xsp_session_get_ref(comSess *sess);
void xsp_session_put_ref(comSess *sess);
int xsp_num_sessions();
void xsp_session_finalize(comSess *sess);

int xsp_session_setup_path(comSess *sess, const void *msg, char ***error_msgs);
int xsp_session_data_open(comSess *sess, const void *msg, char ***error_msgs);

int xsp_session_send_nack(comSess *sess, char **error_msgs);
char *xsp_session_print_nack(const xspMsg *msg);

#include "xsp_listener.h"

void *xsp_default_handle_conn(void *arg);

#ifdef NETLOGGER
int get_next_stream_id();
#endif

#endif
