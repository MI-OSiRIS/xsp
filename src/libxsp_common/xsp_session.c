#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define _GNU_SOURCE
#include <stdio.h>

#include "queue.h"

#include "hashtable.h"
#include "compat.h"
#include "option_types.h"

#include "xsp_modules.h"
#include "xsp_session.h"
#include "xsp_auth.h"
#include "xsp_conn.h"
#include "xsp_protocols.h"
#include "xsp_logger.h"
#include "xsp_settings.h"
#include "xsp_default_settings.h"
#include "xsp_user_settings.h"
#include "xsp_path.h"
#include "xsp_path_handler.h"
#include "xsp_config.h"
#include "xsp_measurement.h"

int xsp_connect_control_channel(comSess *sess, xspHop *curr_child, xspSettings *settings, xspConn **ret_conn, char **ret_error_msg);
int xsp_connect_main(comSess *sess, xspHop *curr_child, xspConn **ret_conn, xspConn **ret_data_conn, char **ret_error_msg);
int xsp_connect_main_protocol(comSess *sess, xspHop *curr_child, xspSettings *policy, const char *protocol, xspConn **ret_conn, char **ret_error_msg);
void __xsp_cb_and_free(comSess *sess, xspMsg *msg);

static LIST_HEAD(listhead, common_session_t) sessions_list;
static pthread_mutex_t sessions_list_lock;
static int session_count;

#ifdef NETLOGGER
int get_next_stream_id() {
  int i;
  for (i=1; i<MAX_ID; i++)
    if (stream_ids[i] == 0) {
      stream_ids[i] = 1;
      return i;
    }
  xsp_info(0, "Ran out of stream_ids for NetLogger!\n");
  return 0;
}
#endif

int xsp_sessions_init() {
	if (pthread_mutex_init(&sessions_list_lock, 0) != 0)
		goto error_exit;

	session_count = 0;

	LIST_INIT(&sessions_list);

	return 0;

error_exit:
	return -1;
}

int xsp_register_session(comSess *sess) {
	int retval = -1;

	pthread_mutex_lock(&sessions_list_lock);
	{
		comSess *curr_sess;

		for(curr_sess = sessions_list.lh_first; curr_sess != NULL; curr_sess = curr_sess->sess_list.le_next) {
			if (!memcmp(curr_sess->id, sess->id, 2*XSP_SESSIONID_LEN + 1)) {
				xsp_err(5, "tried to re-register session %s", sess->id);
				break;
			}
		}

		if (curr_sess == NULL) {
			xsp_info(5, "registering session %s", sess->id);

			LIST_INSERT_HEAD(&sessions_list, sess, sess_list);
			retval = 0;
			session_count++;
		}
	}
	pthread_mutex_unlock(&sessions_list_lock);

	return retval;
}

void xsp_unregister_session(comSess *sess) {

	pthread_mutex_lock(&sessions_list_lock);
	{
		xsp_info(5, "unregistering session %s", sess->id);

		if (sess->sess_list.le_prev != NULL) {
			LIST_REMOVE(sess, sess_list);
			session_count--;
		}
	}
	pthread_mutex_unlock(&sessions_list_lock);
}

comSess *xsp_lookup_session(char *sess_id) {
	comSess *curr_sess;

	xsp_info(5, "finding session %s", sess_id);

	pthread_mutex_lock(&sessions_list_lock);
	{
		for(curr_sess = sessions_list.lh_first; curr_sess != NULL; curr_sess = curr_sess->sess_list.le_next) {
			if (!memcmp(curr_sess->id, sess_id, 2*XSP_SESSIONID_LEN + 1)) {
				xsp_info(5, "found session %s", sess_id);
				break;
			}
		}

		if (curr_sess) {
			__xsp_session_get_ref(curr_sess);
		}
	}
	pthread_mutex_unlock(&sessions_list_lock);

	return curr_sess;
}

comSess **xsp_get_sessions(int *count) {
	comSess *curr_sess;
	comSess **sess_list;

	pthread_mutex_lock(&sessions_list_lock);
	{
		sess_list = malloc(sizeof(comSess *) * session_count);
		if (sess_list) {
			int i = 0;
			for(curr_sess = sessions_list.lh_first; curr_sess != NULL; curr_sess = curr_sess->sess_list.le_next) {
				sess_list[i] = __xsp_session_get_ref(curr_sess);
				i++;
			}

			*count = session_count;
		}
	}
	pthread_mutex_unlock(&sessions_list_lock);

	return sess_list;
}

comSess *xsp_session_get_ref(comSess *sess) {
	comSess *ret_sess;

	pthread_mutex_lock(&sessions_list_lock);
	{
		ret_sess = __xsp_session_get_ref(sess);
	}
	pthread_mutex_unlock(&sessions_list_lock);

	return ret_sess;
}

comSess *__xsp_session_get_ref(comSess *sess) {
	pthread_mutex_lock(&sess->references_lock);
	{
		xsp_info(5, "%s: got reference for session", sess->id);
		sess->references++;
	}
	pthread_mutex_unlock(&sess->references_lock);

	return sess;
}

void xsp_session_put_ref(comSess *sess) {

	pthread_mutex_lock(&sess->references_lock);

	xsp_info(5, "%s: put reference for session", sess->id);
	sess->references--;

	if (sess->references == 0) {
		xsp_info(5, "%s: no more references for session, cleaning up", sess->id);
		xsp_end_session(sess);
	} else {
		pthread_mutex_unlock(&sess->references_lock);
	}
}

void xsp_end_session(comSess *sess) {
	xsp_unregister_session(sess);

	xsp_session_close_connections(sess);

	xsp_free_session(sess);
}

comSess *xsp_convert_xspSess(xspMsg *msg) {
	comSess *new_sess;
	int i;

	new_sess = xsp_alloc_com_sess();
	if (!new_sess) {
		return NULL;
	}

	switch (msg->version) {
	case XSP_v0:
		{
			xspSess *old_sess = (xspSess*)msg->msg_body;
			// copy all the old data over
			memcpy(new_sess->id, old_sess->sess_id, 2*XSP_SESSIONID_LEN+1);
			new_sess->child = malloc(old_sess->child_count * sizeof(xspHop*));
			new_sess->child_count = old_sess->child_count;
			for (i = 0; i < old_sess->child_count; i++)
				xsp_hop_copy(&(new_sess->child[i]), old_sess->child[i]);

			new_sess->version = XSP_v0;
		}
		break;
	case XSP_v1:
		{
			xspBlock **blocks;
			int count;
			// XXX: not sure why the msg contained the xspSess before...
			// the msg should have all the info
			memcpy(new_sess->id, msg->sess_id, 2*XSP_SESSIONID_LEN+1);
			xsp_session_get_blocks(msg, XSP_OPT_HOP, &blocks, &count);
			// XXX: use the first found hop block for now
			if (count > 0) {
				xspHop *hop = (xspHop*)blocks[0]->data;
				// XXX: the hop block can be empty...perhaps change this
				if (hop) {
					new_sess->child = malloc(sizeof(xspHop*));
					new_sess->child_count = 1;
					xsp_hop_copy(&(new_sess->child[0]), hop);
				}
				else {
					new_sess->child = NULL;
					new_sess->child_count = 0;
				}
			}
			else {
				xsp_err(0, "could not find XSP HOP option block");
				return NULL;
			}
			
			new_sess->version = XSP_v1;
		}
		break;
	default:
		xsp_warn(0, "unknown session open msg version");
		break;
	}
	
	// initialize the new data
	new_sess->references = 1;
	
	for(i = 0; i < new_sess->child_count; i++) {
		new_sess->child[i]->session = (xspSess *) new_sess;
	}
	
	LIST_INIT(&new_sess->parent_conns);
	LIST_INIT(&new_sess->child_conns);
	
	LIST_INIT(&new_sess->parent_data_conns);
	LIST_INIT(&new_sess->child_data_conns);
	
	return new_sess;
}

comSess *xsp_alloc_com_sess() {
	comSess *new_sess;

	new_sess = (comSess *) malloc(sizeof(comSess));
	if (!new_sess)
		goto error_exit;

	bzero(new_sess, sizeof(*new_sess));

	if (pthread_mutex_init(&(new_sess->references_lock), 0) < 0)
		goto error_exit2;

#ifdef NETLOGGER
	new_sess->nl_id = get_next_stream_id();
#endif
	return new_sess;

error_exit2:
	free(new_sess);
error_exit:
	return NULL;
}

inline char *xsp_session_get_user(comSess *sess) {
        return sess->user;
}

inline void xsp_session_set_user(comSess *sess, char *user) {
	sess->user = user;
}

inline char *xsp_session_get_id(comSess *sess) {
	return sess->id;
}

inline void xsp_session_close_connections(comSess *sess) {
	xspConn *curr_conn;

	xsp_info(5, "%s: closing connections", sess->id);

	// shutdown the parent connections
	LIST_FOREACH(curr_conn, &(sess->parent_conns), sess_entries) {
		xsp_conn_shutdown(curr_conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
		/*
		if (curr_conn->path != NULL) {
			curr_conn->path->close_channel(curr_conn->path, curr_conn->channel);
			}*/
	}

	// shutdown the children connections
	LIST_FOREACH(curr_conn, &(sess->child_conns), sess_entries) {
		xsp_conn_shutdown(curr_conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
		/*
		if (curr_conn->path != NULL) {
			curr_conn->path->close_channel(curr_conn->path, curr_conn->channel);
			}*/
	}
	
	// shutdown the parent connections
        LIST_FOREACH(curr_conn, &(sess->parent_data_conns), sess_entries) {
                xsp_conn_shutdown(curr_conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
                /*if (curr_conn->path != NULL) {
                        curr_conn->path->close_channel(curr_conn->path, curr_conn->channel);
			}*/
        }

        // shutdown the children connections
        LIST_FOREACH(curr_conn, &(sess->child_data_conns), sess_entries) {
                xsp_conn_shutdown(curr_conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
                /*if (curr_conn->path != NULL) {
                        curr_conn->path->close_channel(curr_conn->path, curr_conn->channel);
			}*/
        }
}

void xsp_free_session(comSess *sess) {
	xspConn *curr_conn;

	xsp_info(5, "%s: freeing session", sess->id);

	while(!LIST_EMPTY(&sess->parent_conns)) {
		curr_conn = LIST_FIRST(&sess->parent_conns);
		LIST_REMOVE(curr_conn, sess_entries);
		xsp_conn_free(curr_conn);
	}

	while(!LIST_EMPTY(&sess->child_conns)) {
		curr_conn = LIST_FIRST(&sess->child_conns);
		LIST_REMOVE(curr_conn, sess_entries);
		xsp_conn_free(curr_conn);
	}
	
	while(!LIST_EMPTY(&sess->parent_data_conns)) {
                curr_conn = LIST_FIRST(&sess->parent_data_conns);
                LIST_REMOVE(curr_conn, sess_entries);
                xsp_conn_free(curr_conn);
        }

        while(!LIST_EMPTY(&sess->child_data_conns)) {
                curr_conn = LIST_FIRST(&sess->child_data_conns);
                LIST_REMOVE(curr_conn, sess_entries);
                xsp_conn_free(curr_conn);
        }

	if (sess->child) {
		int i;

		for(i = 0; i < sess->child_count; i++) {
			xsp_free_hop(sess->child[i], 1);
		}

		free(sess->child);
	}

	//sess->credentials->free(sess->credentials);

	if (sess->user)
		free(sess->user);

	pthread_mutex_destroy(&(sess->references_lock));

#ifdef NETLOGGER
	stream_ids[sess->nl_id] = 0;
#endif
	free(sess);
}

int xsp_num_sessions() {
	int count;
	comSess *curr_sess;

	count = 0;

	pthread_mutex_lock(&sessions_list_lock);
	{
		for(curr_sess = sessions_list.lh_first; curr_sess != NULL; curr_sess = curr_sess->sess_list.le_next)
			count++;
	}
	pthread_mutex_unlock(&sessions_list_lock);

	return count;
}

int xsp_session_get_stat(comSess *sess, uint16_t type, void *optval, size_t *optlen) {
        int retval = -1;

        switch(type) {
	case XSP_STATS_BYTES_READ:
		if (*optlen >= sizeof(uint64_t)) {
			xspConn *conn;
			uint64_t total_bytes;

			total_bytes = 0;

			LIST_FOREACH(conn, &(sess->parent_conns), sess_entries) {
				uint64_t bytes_read = 0;
				size_t bytes_read_size = sizeof(bytes_read);

				if (xsp_conn_get_stat(conn, XSP_STATS_BYTES_READ, &bytes_read, &bytes_read_size) == 0) {
					total_bytes += bytes_read;
				}
			}

			LIST_FOREACH(conn, &(sess->child_conns), sess_entries) {
				uint64_t bytes_read = 0;
				size_t bytes_read_size = sizeof(bytes_read);

				if (xsp_conn_get_stat(conn, XSP_STATS_BYTES_READ, &bytes_read, &bytes_read_size) == 0) {
					total_bytes += bytes_read;
				}
			}

			*((uint64_t *)optval) = total_bytes;
			*optlen = sizeof(total_bytes);
			retval = 0;
		}
		break;
		
	case XSP_STATS_BYTES_WRITTEN:
		if (*optlen >= sizeof(uint64_t)) {
			xspConn *conn;
			uint64_t total_bytes;

			total_bytes = 0;

			LIST_FOREACH(conn, &(sess->parent_conns), sess_entries) {
				uint64_t bytes_written = 0;
				size_t bytes_written_size = sizeof(bytes_written);

				if (xsp_conn_get_stat(conn, XSP_STATS_BYTES_WRITTEN, &bytes_written, &bytes_written_size) == 0) {
					total_bytes += bytes_written;
				}
			}

			LIST_FOREACH(conn, &(sess->child_conns), sess_entries) {
				uint64_t bytes_written = 0;
				size_t bytes_written_size = sizeof(bytes_written);
				
				if (xsp_conn_get_stat(conn, XSP_STATS_BYTES_WRITTEN, &bytes_written, &bytes_written_size) == 0) {
					total_bytes += bytes_written;
				}
			}


			*((uint64_t *)optval) = total_bytes;
			*optlen = sizeof(total_bytes);
			retval = 0;
		}
		break;
        }

        return retval;
}

void xsp_session_finalize(comSess *sess) {
	uint64_t bytes_written;
	size_t bytes_written_size;

	bytes_written_size = sizeof(bytes_written);
}

xspConn *xsp_connect_hop_control(const char *hop_id) {
        char *hostname, *port_str;
        int port;
        xspConn *conn;
        xspSettings *tcp_settings;

        if (xsp_parse_hopid(hop_id, &hostname, &port_str) != 0) {
                xsp_err(0, "invalid hop id: %s", hop_id);
                goto error_exit;
        }

        tcp_settings = xsp_settings_alloc();
        if (!tcp_settings) {
                xsp_err(0, "couldn't allocate tcp protocol settings");
                goto error_exit_parsed;
        }

        sscanf(port_str, "%d", &port);

        if (xsp_settings_set_int_2(tcp_settings, "tcp", "port", port) != 0) {
                xsp_err(0, "couldn't set TCP port");
                goto error_exit_settings;
        }

        conn = xsp_protocol_connect_host(hostname, "tcp", tcp_settings);
        if (!conn) {
                xsp_err(0, "couldn't connect to %s on port %d with tcp", hostname, port);
                goto error_exit_settings;
        }

        return conn;

 error_exit_settings:
        xsp_settings_free(tcp_settings);
 error_exit_parsed:
        free(hostname);
        free(port_str);
 error_exit:
        return NULL;
}

int xsp_get_settings(comSess *sess, xspHop *curr_child, xspSettings **ret_settings) {
	xspSettings *default_settings = NULL;
	xspSettings *route_settings = NULL;
	xspSettings *user_settings = NULL;
	xspSettings *new_settings = NULL;
	xspSettings *settings = NULL;

	settings = xsp_settings_alloc();

	default_settings = xsp_default_settings(XSP_BOTH);
	if (default_settings) {
		new_settings = xsp_settings_merge(settings, default_settings);
		if (!new_settings) {
			xsp_err(5, "couldn't merge default settings with user settings");
			goto error_exit_settings;
		}

		xsp_settings_free(settings);

		settings = new_settings;
	}

	default_settings = xsp_default_settings(XSP_OUTGOING);
	if (default_settings) {
		new_settings = xsp_settings_merge(settings, default_settings);
		if (!new_settings) {
			xsp_err(5, "couldn't merge default settings with user settings");
			goto error_exit_settings;
		}

		xsp_settings_free(settings);

		settings = new_settings;
	}

	user_settings = xsp_user_settings(sess->credentials->get_user(sess->credentials), XSP_BOTH);
        if (user_settings) {
                new_settings = xsp_settings_merge(settings, user_settings);
                if (!new_settings) {
                        xsp_err(5, "couldn't merge default settings with user settings");
                        goto error_exit_settings;
                }

		xsp_settings_free(settings);

                settings = new_settings;
        }

        user_settings = xsp_user_settings(sess->credentials->get_user(sess->credentials), XSP_OUTGOING);
        if (user_settings) {
                new_settings = xsp_settings_merge(settings, user_settings);
                if (!new_settings) {
                        xsp_err(5, "couldn't merge default settings with user settings");
                        goto error_exit_settings;
                }

                xsp_settings_free(settings);

                settings = new_settings;
        }

	if (sess->requested_settings) {
		new_settings = xsp_settings_merge(settings, route_settings);
		if (!new_settings) {
			xsp_err(5, "couldn't merge settings with requested settings");
			goto error_exit_settings;
		}

		xsp_settings_free(settings);
		settings = new_settings;
	}

	*ret_settings = settings;

	return 0;

error_exit_settings:
	xsp_settings_free(settings);
	return -1;
}

int xsp_session_setup_path(comSess *sess, const void *arg, char ***error_msgs) {
	int i;
	char *error_msg;
	xspPath *path;
	xspChannel *channel;
	xspSettings *settings = NULL;
	xspConn *parent_conn;

	xspBlock **blocks;
	int block_count;
	xspNetPath *net_path;
	xspNetPathRule *rule;

	xsp_session_get_blocks((xspMsg*)arg, XSP_OPT_PATH, &blocks, &block_count);
	// XXX: taking only the first block!
	net_path = blocks[0]->data;
	
	parent_conn = LIST_FIRST(&sess->parent_conns);

	xsp_info(0, "Setting up path type %s for client=%s",
		 net_path->type, parent_conn->description);

	// just get main paths section from the config for now
	// we can also make our own settings from the session values
        if (xsp_main_settings_get_section("paths", &settings) != 0) {
                xsp_info(5, "No path sections found, going with defaults");
                settings = xsp_settings_alloc();
        }

	if (!strcasecmp(net_path->type, "TERAPATHS") && sess->child_count) {
	  // set src and dst in the settings to start
		xsp_settings_set_2(settings, "terapaths", "src", strtok(parent_conn->description, "/"));
		xsp_settings_set_2(settings, "terapaths", "dst", strtok(xsp_hop_getid(sess->child[0]), "/"));
	}

	if (xsp_get_path(net_path->type, settings, &path, &error_msg) != 0) {
		xsp_err(0, "couldn't get path information: %s", error_msg);
		goto error_exit;
	}

	if (net_path->rule_count) {
		// setup channels for each rule in the net path
		for (i = 0; i < net_path->rule_count; i++) {
			if (path->new_channel(path, net_path->rules[i], &channel, &error_msg) != 0) {
				xsp_err(0, "couldn't allocate a channel: %s", error_msg);
				goto error_exit;
			}
		}
	}
	// setup a blank rule that uses local settings
	else {
		xspNetPathRule rule;
		memset(&rule, 0, sizeof(xspNetPathRule));
		
		// add some rule stuff here

		if (path->new_channel(path, &rule, &channel, &error_msg) != 0) {
			xsp_err(0, "couldn't allocate a channel: %s", error_msg);
			goto error_exit;
		}
	}
		
	return 0;

 error_exit:
	*error_msgs[0] = error_msg;
	return -1;
}

int xsp_session_data_open(comSess *sess, const void *arg, char ***error_msgs) {
        xspConn *parent_conn;
        xspDataOpen *dopen;
        xspBlock *block;
        xspBlock **blocks;
        int block_count;

	xsp_session_get_blocks((xspMsg*)arg, XSP_OPT_DATA, &blocks, &block_count);
	// XXX: taking only the first block!
	block = blocks[0];

	dopen = (xspDataOpen *)block->data;
	
        parent_conn = LIST_FIRST(&sess->parent_conns);

        xsp_info(0, "Setting up data proto %s for SRC=%s to DST=%s\n",
		  dopen->proto, parent_conn->description, xsp_hop_getid(sess->child[0]));
	
	// explicitly open a data connection

	return 0;
}

// handle any generic APP_DATA option blocks
// registered option ranges are included in include/option_types.h for now
int xsp_session_app_data(comSess *sess, const void *arg, char ***error_msgs) {
	char *error_msg = NULL;
	char *mstring = NULL;
        xspConn *parent_conn;
	xspModule *module;

	xspBlock *ret_block;
	xspBlock *block;
        xspBlock **blocks;
	int block_count;

	parent_conn = LIST_FIRST(&sess->parent_conns);

	xsp_session_get_blocks((xspMsg*)arg, -1, &blocks, &block_count);
	// XXX: taking only the first block!
	block = blocks[0];
	
	// each module should register some range of option blocks
	// then the module option handler (callback) should get invoked based on the type
	// we'll switch on the defined option types for now...
	if (block->type >= PHOTON_MIN && 
	    block->type <= PHOTON_MAX) {
		mstring = "photon";
	}

	if (block->type >= NLMI_MIN &&
            block->type <= NLMI_MAX) {
		mstring = "nlmi";
	}

	if (block->type >= GLOBUS_XIO_MIN &&
            block->type <= GLOBUS_XIO_MAX) {
		mstring = "globus_xio";
        }

	if (!mstring) {
		xsp_err(0, "unrecognized option block type\n");
		goto error_exit;
	}

	if ((module = xsp_find_module(mstring)) != NULL)
		module->opt_handler(sess, block, &ret_block);
	else {
		
		xsp_err(0, "module not loaded: %s", mstring);
		goto error_exit;
	}
	
	// send back a response if necessary
	if (ret_block) {
		xsp_conn_send_msg(parent_conn, sess->version, XSP_MSG_APP_DATA, XSP_OPT_NULL, ret_block);
		xsp_free_block(ret_block, XSP_BLOCK_KEEP_DATA);
	}

	return 0;
	
 error_exit:
	*error_msgs[0] = error_msg;
	return -1;
}

int xsp_session_send_nack(comSess *sess, char **error_msgs) {
	int i;
	char nack_msg[1024];
	xspConn *conn = NULL;

	conn = LIST_FIRST(&sess->parent_conns);
        if (!conn) {
                xsp_err(0, "no active session conn, aborting");
		return -1;
        }
	
	nack_msg[0] = '\0';
	if (!error_msgs) {
		strlcat(nack_msg, "An internal error occurred", sizeof(nack_msg));
	} else {
		for(i = 0; i < sess->child_count+1; i++) {
			if (error_msgs[i]) {
				//strlcat(nack_msg, "Connect to ", sizeof(nack_msg));
				//strlcat(nack_msg, xsp_hop_getid(sess->child[i]), sizeof(nack_msg));
				strlcat(nack_msg, "failure: ", sizeof(nack_msg));
				strlcat(nack_msg, error_msgs[i], sizeof(nack_msg));
				strlcat(nack_msg, "\n", sizeof(nack_msg));
			}
		}
	}
	
	xsp_info(5, "Sending NACK: %s", nack_msg);
	xsp_conn_send_msg(conn, sess->version, XSP_MSG_SESS_NACK, XSP_OPT_NACK, nack_msg);
	return 0;
}

int xsp_set_proto_cb(comSess *sess, void *(*fn) (comSess *, xspMsg *)) {
	sess->proto_cb = fn;
	return 0;
}

comSess *xsp_wait_for_session(xspConn *conn, comSess **ret_sess, int (*cb) (comSess *)) {
	xspMsg *msg;
	comSess *sess;
	xspCreds *credentials;
	xspAuthType *auth_type;
	int authenticated;
        int have_session;
	int sess_close;
	int version = XSP_v1;
	
	authenticated = FALSE;
	have_session = FALSE;
	sess_close = FALSE;
	
	xsp_info(0,"xsp_default_handle_conn");
	do {
		msg = xsp_conn_get_msg(conn, 0);
		if (!msg) {
			xsp_err(5, "Did not receive properly formed message.");
			goto error_exit;
		}
		
		version = msg->version;

		switch(msg->type) {
		
		case XSP_MSG_SESS_CLOSE:
			{
				// so we can close the connection after ping/pong
				xsp_info(10, "Close session message received.");
				xsp_free_msg(msg);
				goto error_exit;
			}
			break;
			
		case XSP_MSG_PING:
			{
				xsp_info(10, "PING/PONG");
				xsp_free_msg(msg);
				xsp_conn_send_msg(conn, version, XSP_MSG_PONG, XSP_OPT_NULL, NULL);
			}
			break;

		case XSP_MSG_AUTH_TYPE:
			{
				if (xsp_authenticate_connection(conn, msg, &credentials) != 0) {
					xsp_err(0, "Authentication failed.");
					goto error_exit;
				}
				xsp_free_msg(msg);
				authenticated = TRUE;
			}
			break;
			
		case XSP_MSG_SESS_OPEN:
			{
				if (!authenticated) {
					xsp_err(0, "Session open before authentication.");
					xsp_free_msg(msg);
					goto error_exit;
				}
				
				sess = xsp_convert_xspSess(msg);
				if (!sess) {
					xsp_err(0, "xspSess conversion failed");
					xsp_free_msg(msg);
					goto error_exit;
				}
				have_session = TRUE;
				xsp_free_msg(msg);
			}
			break;
		       
		default:
			{
				xsp_err(0, "Invalid message received");
				free(msg);
				goto error_exit;
			}
		}

	} while (!authenticated || !have_session);

	xsp_info(0, "new session: %s", xsp_session_get_id(sess));
	
	LIST_INSERT_HEAD(&sess->parent_conns, conn, sess_entries);
	
	sess->credentials = credentials;
	xsp_session_set_user(sess, strdup(credentials->get_user(credentials)));
	
	xsp_info(0, "new user: \"%s\"(%s) from \"%s\"",
		 xsp_session_get_user(sess),
		 credentials->get_email(credentials),
		 credentials->get_institution(credentials));
		
	gettimeofday(&sess->start_time, NULL);
	
	// XXX: should probably setup child hops here before we ACK
	// but we leave that task for the callback for now
	if (cb) {
		if (cb(sess) != 0) {
			goto error_exit;
		}
	}

	xsp_conn_set_session_status(conn, STATUS_CONNECTED);

	// send an ACK back once session is ready
	xsp_conn_send_msg(conn, sess->version, XSP_MSG_SESS_ACK, XSP_OPT_NULL, NULL);
	
	*ret_sess = sess;
	return sess;
	
 error_exit:
        xsp_conn_shutdown(conn, (XSP_SEND_SIDE | XSP_RECV_SIDE));
	xsp_conn_free(conn);
	*ret_sess = NULL;
	return NULL;
}

int xsp_proto_loop(comSess *sess) {
	xspMsg *msg;
	xspConn *conn;
	char **error_msgs;
	int sess_close = 0;
	int version = XSP_v1;

	conn = LIST_FIRST(&sess->parent_conns);
	if (!conn) {
		xsp_err(0, "no active session conn, aborting");
		goto error_exit;
	}
			 
	error_msgs = (char**)malloc(sess->child_count+1 * sizeof(char*));

	// now start another protocol loop
	do {
		msg = xsp_conn_get_msg(conn, 0);
                if (!msg) {
                        xsp_err(5, "Did not receive properly formed message.");
                        goto error_exit;
                }

		version = msg->version;

                switch(msg->type) {
			
		case XSP_MSG_SESS_OPEN:
			{
				__xsp_cb_and_free(sess, msg);
				xsp_conn_send_msg(conn, version, XSP_MSG_SESS_ACK, XSP_OPT_NULL, NULL);
			}
			break;
                case XSP_MSG_SESS_CLOSE:
                        {
                                xsp_info(10, "Close session message received.");
				__xsp_cb_and_free(sess, msg);
                                sess_close = 1;
                        }
                        break;
		case XSP_MSG_NET_PATH:
			{
				if (xsp_session_setup_path(sess, msg, &error_msgs) < 0) {
					xsp_session_send_nack(sess, error_msgs);
					xsp_free_msg(msg);
					continue;
				}
				__xsp_cb_and_free(sess, msg);
				xsp_conn_send_msg(conn, version, XSP_MSG_SESS_ACK, XSP_OPT_NULL, NULL);
			}
			break;
                case XSP_MSG_PING:
		        {
			        xsp_info(10, "PING/PONG");
				__xsp_cb_and_free(sess, msg);
				xsp_conn_send_msg(conn, version, XSP_MSG_PONG, XSP_OPT_NULL, NULL);
			}
			break;
		case XSP_MSG_SLAB_INFO:
			{
				__xsp_cb_and_free(sess, msg);
				//xsp_conn_send_msg(conn, version, XSP_MSG_SESS_ACK, XSP_OPT_NULL, NULL);
			}
			break;
		case XSP_MSG_DATA_CHAN:
			{
				if (xsp_session_data_open(sess, msg, &error_msgs) < 0) {
					xsp_session_send_nack(sess, error_msgs);
					xsp_free_msg(msg);
					continue;
				}
				__xsp_cb_and_free(sess, msg);
				xsp_conn_send_msg(conn, version, XSP_MSG_SESS_ACK, XSP_OPT_NULL, NULL);
			}
			break;
		case XSP_MSG_APP_DATA:
			{
				if (xsp_session_app_data(sess, msg, &error_msgs) < 0) {
					xsp_session_send_nack(sess, error_msgs);
					xsp_free_msg(msg);
					continue;
				}
				__xsp_cb_and_free(sess, msg);
			}
			break;
		default:
                        {
                                xsp_err(0, "Invalid message received");
                                free(msg);
                                goto error_exit;
                        }
                }
	} while (!sess_close);

	gettimeofday(&sess->end_time, NULL);

	xsp_info(5, "session finished: %s", xsp_session_get_id(sess));

	xsp_session_finalize(sess);
	xsp_session_put_ref(sess);

	return 0;

 error_exit:
	xsp_end_session(sess);
	return -1;
}

void __xsp_cb_and_free(comSess *sess, xspMsg *msg) {
	if (sess->proto_cb)
		sess->proto_cb(sess, msg);
	xsp_free_msg(msg);
}

int xsp_session_get_blocks(const xspMsg *msg, int opt_type, xspBlock ***ret_blocks, int *count) {
	int num;

	switch (msg->version) {
	case XSP_v0:
		{
			*ret_blocks = malloc(sizeof(xspBlock*));
			*ret_blocks[0] = (xspBlock *)msg->msg_body;
			num = 1;
		}
		break;
	case XSP_v1:
		xsp_block_list_find((xspBlockList*)msg->msg_body, opt_type, ret_blocks, &num);
		break;
	default:
		xsp_err(0, "unkown message version");
		break;
	}
	
	*count = num;
	return num;
}
		
char *xsp_session_print_nack(const xspMsg *msg) {
	switch (msg->version) {
        case XSP_v0:
                return (char*)msg->msg_body;
                break;
        case XSP_v1:
                {
                        xspBlock **blocks;
                        int count;
                        xsp_block_list_find((xspBlockList*)msg->msg_body, XSP_OPT_NACK, &blocks, &count);
                        // XXX: taking only the first block found!
                        if (count)
                                return (char*)blocks[0]->data;
                        else
                                return NULL;
                }
                break;
        default:
                xsp_err(0, "unknown version");
                break;
        }

        return NULL;
}
