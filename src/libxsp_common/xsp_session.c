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
#include "xsp_conn.h"
#include "xsp_protocols.h"
#include "xsp_logger.h"
#include "xsp_settings.h"
#include "xsp_default_settings.h"
#include "xsp_path.h"
#include "xsp_path_handler.h"
#include "xsp_config.h"

#define XSP_BUF_SIZE			1048576

int xsp_connect_control_channel(comSess *sess, xspHop *curr_child, xspSettings *settings, xspConn **ret_conn, char **ret_error_msg);
int xsp_connect_main(comSess *sess, xspHop *curr_child, xspConn **ret_conn, xspConn **ret_data_conn, char **ret_error_msg);
int xsp_connect_main_protocol(comSess *sess, xspHop *curr_child, xspSettings *policy, const char *protocol, xspConn **ret_conn, char **ret_error_msg);

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

comSess *xsp_convert_xspSess(xspSess *old_sess) {
	comSess *new_sess;
	int i;

	new_sess = xsp_alloc_com_sess();
	if (!new_sess) {
		return NULL;
	}

	// copy all the old data over
	bcopy(old_sess->sess_id, new_sess->id, 2*XSP_SESSIONID_LEN+1);
	new_sess->child = old_sess->child;
	new_sess->child_count = old_sess->child_count;

	// initialize the new data
	new_sess->references = 1;

	for(i = 0; i < new_sess->child_count; i++) {
		new_sess->child[i]->session = (comSess *) new_sess;
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


void xsp_session_finalize(comSess *sess) {
	uint64_t bytes_written;
	size_t bytes_written_size;

	bytes_written_size = sizeof(bytes_written);
}



int xsp_get_settings(comSess *sess, xspHop *curr_child, xspSettings **ret_settings) {
	xspSettings *default_settings = NULL;
	xspSettings *route_settings = NULL;
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

int xsp_session_setup_path(comSess *sess, const void *msg, char ***error_msgs) {
	char *error_msg;
	uint32_t bandwidth;
	xspPath *path;
	xspChannel *channel;
	xspSettings *settings = NULL;
	xspConn *parent_conn;
	
	xspBlockHeader *block = (xspBlockHeader *)msg;
	char *path_type = malloc(block->length*sizeof(char));
	strncpy(path_type, block->blob, block->length);

	parent_conn = LIST_FIRST(&sess->parent_conns);

	xsp_info(0, "Setting up path type %s for SRC=%s to DST=%s\n",
		  path_type, parent_conn->description, xsp_hop_getid(sess->child[0]));

	// just get main paths section from the config for now
	// we can also make our own settings from the session values
        if (xsp_main_settings_get_section("paths", &settings) != 0) {
                xsp_info(5, "No path sections found, going with defaults");
                settings = xsp_settings_alloc();
        }

	if (!strcmp(path_type, "TERAPATHS")) {
		// set src and dst in the settings to start
		xsp_settings_set_2(settings, "terapaths", "src", strtok(parent_conn->description, "/"));
		xsp_settings_set_2(settings, "terapaths", "dst", strtok(xsp_hop_getid(sess->child[0]), "/"));
	}

	if (xsp_get_path(path_type, settings, &path, &error_msg) != 0) {
		xsp_err(0, "couldn't get path information: %s", error_msg);
		goto error_exit;
	}
	if (path->new_channel(path, bandwidth, &channel, &error_msg) != 0) {
		xsp_err(0, "couldn't allocate a channel: %s", error_msg);
		goto error_exit;
	}
	
	return 0;

 error_exit:
	*error_msgs[0] = error_msg;
	return -1;
}

int xsp_session_data_open(comSess *sess, const void *msg, char ***error_msgs) {
        //char *error_msg;
        //xspSettings *settings = NULL;
        xspConn *parent_conn;
        xspDataOpenHeader *dopen = (xspDataOpenHeader *)msg;
	
        parent_conn = LIST_FIRST(&sess->parent_conns);

        xsp_info(0, "Setting up data proto %s for SRC=%s to DST=%s\n",
		  dopen->proto, parent_conn->description, xsp_hop_getid(sess->child[0]));
	
	// explicitly open a data connection

	return 0;
}

// handle any generic APP_DATA option blocks
// registered option ranges are included in include/option_types.h for now
int xsp_session_app_data(comSess *sess, const void *msg, char ***error_msgs) {
	char *error_msg = NULL;
        xspConn *parent_conn;
	xspModule *module;

        xspBlockHeader *block;
	xspBlockHeader *ret_block;

	char *mstring = NULL;

	parent_conn = LIST_FIRST(&sess->parent_conns);

	block = (xspBlockHeader *)msg;
	
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
		xsp_conn_send_msg(parent_conn, XSP_MSG_APP_DATA, ret_block);
		free(ret_block);
	}

	return 0;
	
 error_exit:
	*error_msgs[0] = error_msg;
	return -1;
}
