#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#ifdef HAVE_SENDFILE_H
#include <sys/sendfile.h>
#endif
#include <unistd.h>

#include "compat.h"

#include "oscars.h"

#include "xspd_oscars_basic.h"

#include "xspd_modules.h"
#include "xspd_conn.h"
#include "xspd_logger.h"
#include "xspd_session.h"
#include "xspd_path_handler.h"
#include "hashtable.h"
#include "xspd_config.h"

typedef struct xspd_oscars_timeout_args {
	xspdPath *path;
	int tag;
	int timeout;
} xspdOSCARSTimeoutArgs;

int xspd_oscars_shared_init();
static int xspd_oscars_shared_allocate_path(const xspdSettings *settings, xspdPath **ret_path, char **ret_error_msg);
static char *xspd_oscars_generate_path_id(const xspdSettings *settings, char **ret_error_msg);
static int xspd_oscars_shared_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg);
static int xspd_oscars_shared_close_channel(xspdPath *path, xspdChannel *channel);
static int xspd_oscars_shared_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg);
static void xspd_oscars_shared_free_path(xspdPath *path);

static int __xspd_oscars_shared_new_channel(xspdPath *path, uint32_t size, xspdChannel **new_channel, char **ret_error_msg);
static int __xspd_oscars_shared_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg);
static int __xspd_oscars_shared_close_channel(xspdPath *path, xspdChannel *channel);

static xspdOSCARSPath *xspd_alloc_oscars_path();
static void xspd_free_oscars_path(xspdOSCARSPath *pi);
static void xspd_oscars_reset_path_info();

static xspdOSCARSTimeoutArgs *xspd_alloc_oscars_timeout_args();
static void xspd_timeout_handler(void *arg);

xspdModule xspd_oscars_shared_module = {
	.desc = "OSCARS Module",
	.dependencies = "",
	.init = xspd_oscars_shared_init
};

xspdPathHandler xspd_oscars_shared_path_handler = {
	.name = "OSCARS",
	.allocate = xspd_oscars_shared_allocate_path,
	.get_path_id = xspd_oscars_generate_path_id,
};

xspdModule *module_info() {
	return &xspd_oscars_shared_module;
}

int xspd_oscars_shared_init() {
	return xspd_add_path_handler(&xspd_oscars_shared_path_handler);
}

static char *xspd_oscars_generate_path_id(const xspdSettings *settings, char **ret_error_msg) {
	char *oscars_server;
	char *oscars_src_id;
	char *oscars_dst_id;
	int oscars_vlan_id;
	char *path_id;

	if (xspd_settings_get_2(settings, "oscars", "server", &oscars_server) != 0) {
		if (ret_error_msg) {
			xspd_err(0, "No OSCARS server specified");
			*ret_error_msg = strdup("No OSCARS server specified");
		}

		goto error_exit;
	}

	if (xspd_settings_get_2(settings, "oscars", "src_id", &oscars_src_id) != 0) {
		if (ret_error_msg) {
			xspd_err(0, "No OSCARS source identifier specified");
			*ret_error_msg = strdup("No OSCARS source identifier specified");
		}

		goto error_exit;
	}

	if (xspd_settings_get_2(settings, "oscars", "dst_id", &oscars_dst_id) != 0) {
		if (ret_error_msg) {
			xspd_err(0, "No OSCARS destination identifier specified");
			*ret_error_msg = strdup("No OSCARS destination identifier specified");
		}

		goto error_exit;
	}

	if (xspd_settings_get_int_2(settings, "oscars", "vlan_id", &oscars_vlan_id) != 0) {
		oscars_vlan_id = -1;
	}

	if (strcmp(oscars_src_id, oscars_dst_id) > 0) {
		char *tmp = oscars_src_id;
		oscars_src_id = oscars_dst_id;
		oscars_dst_id = tmp;
	}

	if (xspd_settings_get_2(settings, "oscars", "path_id", &path_id) != 0) {
		if (ret_error_msg) {
			if (asprintf(&path_id, "%s->%s@%s:%d", oscars_src_id, oscars_dst_id, oscars_server, oscars_vlan_id) <= 0) {
				goto error_exit;
			}
		}
	}

	return path_id;

error_exit:
	return NULL;
}

static int xspd_oscars_shared_allocate_path(const xspdSettings *settings, xspdPath **ret_path, char **ret_error_msg) {
	xspdPath *path;
	xspdOSCARSPath *pi;
	char *oscars_server;
	char *oscars_src_id;
	char *oscars_dst_id;
	char *oscars_client_dir;
	char *oscars_java_path;
	char *oscars_axis_path;
	int oscars_src_tagged;
	int oscars_dst_tagged;
	int oscars_duration;
	int oscars_vlan_id;
	int oscars_sleep_time;
	int oscars_clock_offset;
	int oscars_teardown_timeout;
	int oscars_intercircuit_pause_time;
	char *path_type_str;
	int path_type;

	if (xspd_settings_get_2(settings, "oscars", "server", &oscars_server) != 0) {
		xspd_err(0, "No OSCARS server specified");
		goto error_exit;
	}

	if (xspd_settings_get_int_2(settings, "oscars", "duration", &oscars_duration) != 0) {
		xspd_err(0, "No duration specified for OSCARS reservation");
		goto error_exit;
	}

	if (xspd_settings_get_2(settings, "oscars", "client_directory", &oscars_client_dir) != 0) {
		xspd_err(0, "No OSCARS client directory specified");
		goto error_exit;
	}

	if (xspd_settings_get_2(settings, "oscars", "java_path", &oscars_java_path) != 0) {
		xspd_info(8, "No java binary specified, using default binary in path");
		oscars_java_path = NULL;
	}

	if (xspd_settings_get_2(settings, "oscars", "axis_path", &oscars_axis_path) != 0) {
		oscars_axis_path = NULL;
	}


	if (xspd_settings_get_2(settings, "oscars", "src_id", &oscars_src_id) != 0) {
		xspd_err(0, "No OSCARS source identifier specified");
		goto error_exit;
	}

	if (xspd_settings_get_2(settings, "oscars", "dst_id", &oscars_dst_id) != 0) {
		xspd_err(0, "No OSCARS destination identifier specified");
		goto error_exit;
	}

	if (xspd_settings_get_2(settings, "oscars", "type", &path_type_str) != 0) {
		xspd_info(8, "Using private path");
		path_type_str = "private";
	}
	
	if (strcmp(path_type_str, "private") == 0) {
		xspd_info(0, "Using private path");
		path_type = PATH_PRIVATE;
	} else if (strcmp(path_type_str, "shared") == 0) {
		path_type = PATH_SHARED;
		xspd_info(0, "Using shared path");
	} else {
		xspd_err(0, "Invalid path type. must be 'private' or 'shared'");
		goto error_exit;
	}

	if (xspd_settings_get_int_2(settings, "oscars", "vlan_id", &oscars_vlan_id) != 0) {
		oscars_vlan_id = -1;
	}

	if (xspd_settings_get_int_2(settings, "oscars", "clock_offset", &oscars_clock_offset) != 0) {
		oscars_clock_offset = 0;
	}

	if (xspd_settings_get_int_2(settings, "oscars", "teardown_timeout", &oscars_teardown_timeout) != 0) {
		oscars_teardown_timeout = 0;
	}

	if (xspd_settings_get_int_2(settings, "oscars", "intercircuit_pause_time", &oscars_intercircuit_pause_time) != 0) {
		oscars_intercircuit_pause_time = 0;
	}

	if (xspd_settings_get_int_2(settings, "oscars", "sleep_time", &oscars_sleep_time) != 0) {
		oscars_sleep_time = 5;
	}
	
	if (xspd_settings_get_bool_2(settings, "oscars", "src_tagged", &oscars_src_tagged) != 0) {
		oscars_src_tagged = 1;
	}

	if (xspd_settings_get_bool_2(settings, "oscars", "dst_tagged", &oscars_dst_tagged) != 0) {
		oscars_dst_tagged = 1;
	}

	path = xspd_alloc_path();
	if (!path)
		goto error_exit;

	pi = xspd_alloc_oscars_path();
	if (!pi)
		goto error_exit_path;

	pi->url = oscars_server;
	pi->src = oscars_src_id;
	pi->src_tagged = oscars_src_tagged;
	pi->dst = oscars_dst_id;
	pi->dst_tagged = oscars_dst_tagged;
	pi->java_binary = oscars_java_path;
	pi->axis_path = oscars_axis_path;
	pi->client_dir = oscars_client_dir;
	pi->duration = oscars_duration;
	pi->vlan_id = oscars_vlan_id;
	pi->clock_offset = oscars_clock_offset;
	pi->sleep_time = oscars_sleep_time;
	pi->type = path_type;
	pi->teardown_timeout = oscars_teardown_timeout;
	pi->intercircuit_pause_time = oscars_intercircuit_pause_time;
	pi->shutdown_time = 0;
	
	path->path_private = pi;
	path->new_channel = xspd_oscars_shared_new_channel;
	path->resize_channel = xspd_oscars_shared_resize_channel;
	path->close_channel = xspd_oscars_shared_close_channel;
	path->free = xspd_oscars_shared_free_path;

	*ret_path = path;

	return 0;

error_exit_path:
	xspd_free_path(path);
error_exit:
	return -1;
}

static int xspd_oscars_shared_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg) {
	int retval;
	char *error_msg = NULL;

	pthread_mutex_lock(&(path->lock));
	{
		retval = __xspd_oscars_shared_new_channel(path, size, channel, &error_msg);
	}
	pthread_mutex_unlock(&(path->lock));

	if (error_msg)
		*ret_error_msg = error_msg;

	return retval;
}

static int xspd_oscars_shared_close_channel(xspdPath *path, xspdChannel *channel) {
	int retval;

	pthread_mutex_lock(&(path->lock));
	{
		retval = __xspd_oscars_shared_close_channel(path, channel);
	}
	pthread_mutex_unlock(&(path->lock));

	return retval;
}

static int xspd_oscars_shared_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg) {
	int retval;
	char *error_msg = NULL;

	pthread_mutex_lock(&(path->lock));
	{
		retval = __xspd_oscars_shared_resize_channel(path, channel, new_size, &error_msg);
	}
	pthread_mutex_unlock(&(path->lock));

	if (error_msg)
		*ret_error_msg = error_msg;

	return retval;
}

static int __xspd_oscars_shared_new_channel(xspdPath *path, uint32_t size, xspdChannel **new_channel, char **ret_error_msg) {
	char *reservation_id;
	xspdOSCARSPath *pi = path->path_private;
	xspdChannel *channel;
	char *error_msg;
	char *status;
	int active = 0;

	path->tag++;
	pthread_cond_signal(&(path->timeout_cond));

	xspd_info(10, "%s: allocating new channel of size: %d", path->description, size);

	channel = xspd_alloc_channel();
	if (!channel) {
		xspd_err(0, "%s: couldn't allocate channel object", path->description);
		goto error_exit;
	}
	
	if (pi->intercircuit_pause_time > 0) {
		time_t curr_time;
		
		time(&curr_time);
		
		if (curr_time < (pi->shutdown_time + pi->intercircuit_pause_time)) {
			xspd_info(5, "%s: sleeping for %d seconds waiting for the circuit to become available", path->description, ((pi->shutdown_time + pi->intercircuit_pause_time) - curr_time));
			sleep((pi->shutdown_time + pi->intercircuit_pause_time) - curr_time);
		}
	}
	
	while (pi->status == OSCARS_STARTING) {
		pthread_cond_wait(&(pi->setup_cond), &(path->lock));
	}
	
	if (pi->status == OSCARS_DOWN) {
		time_t stime, etime;
		uint32_t new_bandwidth = size;
		
		pi->status = OSCARS_STARTING;		
		
		time(&stime);	
		stime += pi->clock_offset;
		etime = stime + pi->duration;
		
		xspd_info(0, "%s: the OSCARS path is down, allocating a new one", path->description);
		
		if (oscars_reserve_path(pi->java_binary, pi->axis_path, pi->url, pi->client_dir, pi->src, pi->src_tagged, pi->dst, pi->dst_tagged, stime, etime, size, pi->vlan_id, "XSPD Test Path", &reservation_id, &error_msg) != 0){
			pthread_cond_signal(&(pi->setup_cond));
			pi->status = OSCARS_DOWN;	
			xspd_event("oscars.circuit.reserve.failure", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, size, error_msg);
			xspd_err(0, "%s: couldn't reserve OSCARS path: %s", path->description, error_msg);
			*ret_error_msg = error_msg;
			goto error_exit_channel;
		}
		
		xspd_info(10, "Sleeping for %d seconds", pi->sleep_time);
		sleep(pi->sleep_time);
		
		//if (oscars_create_path(pi->java_binary, pi->axis_path, pi->url, pi->client_dir, reservation_id, &error_msg) != 0) {
		//pthread_cond_signal(&(pi->setup_cond));
		//pi->status = OSCARS_DOWN;
		//xspd_event("oscars.circuit.create.failure", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, size, error_msg);
		//xspd_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
		//*ret_error_msg = error_msg;
		//goto error_exit_reservation;
		//}
		
	       	while (!active){
			if (oscars_query_path_status(pi->java_binary, pi->axis_path, pi->url, pi->client_dir, reservation_id, &status, &error_msg) != 0) {
				pthread_cond_signal(&(pi->setup_cond));
				pi->status = OSCARS_DOWN;
				xspd_event("oscars.circuit.create.failure", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, size, error_msg);
				xspd_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
				*ret_error_msg = error_msg;
				goto error_exit_reservation;
			}
			
			if (strcmp(status,"ACTIVE") == 0){
				active=1;
			}
			
			if (strcmp(status,"FAILED") ==0){
				pthread_cond_signal(&(pi->setup_cond));
				pi->status = OSCARS_DOWN;
				xspd_event("oscars.circuit.create.failure", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, size, error_msg);
				xspd_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
				*ret_error_msg = error_msg;
				goto error_exit_reservation;
			}
			
			xspd_info(10, "Sleeping for %d seconds", pi->sleep_time);
			sleep(pi->sleep_time);
		}
		
		xspd_event("oscars.circuit.allocated", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, size, error_msg);
		
		xspd_info(10, "Sleeping for %d seconds", pi->sleep_time);
		sleep(pi->sleep_time);
		
		xspd_info(0, "%s: allocated new path of size %d Mbit/s(Start Time: %lu End Time: %lu). Id: %s", path->description, new_bandwidth, (unsigned long) stime, (unsigned long) etime, reservation_id);
		
		// save the path information
		pi->reservation_id = reservation_id;
		pi->bandwidth = new_bandwidth;
		
		pi->status = OSCARS_UP;
		
		pthread_cond_signal(&(path->timeout_cond));
	} else if (pi->type == PATH_SHARED || pi->bandwidth >= pi->bandwidth_used + size) {
		xspd_info(0, "%s: reusing existing path. Amount used: %d/%d", path->description, pi->bandwidth_used, pi->bandwidth);
	} else {
	      /*
		uint32_t new_bandwidth;

		xspd_info(0, "%s: resizing path from %d to %d", path->description, pi->bandwidth, new_bandwidth);

		if (oscars_resize_path(pi->url, pi->client_dir, pi->reservation_id, new_bandwidth, &reservation_id) != 0) {
			xspd_err(0, "%s: couldn't resize path from %d to %d", path->description, pi->bandwidth, pi->bandwidth_used + size);
			goto error_exit_channel;
		}

		xspd_info(10, "%s: path resized to %d Mbit/s. New id: %s", path->description, new_bandwidth, reservation_id);

		free(pi->reservation_id);
		pi->reservation_id = reservation_id;
		pi->bandwidth = new_bandwidth;
*/
		xspd_err(0, "%s: Can't resize paths", path->description);
		goto error_exit_channel;
	}
	
	pi->bandwidth_used += size;
	
	// set the channels bandwidth
	channel->bandwidth = size;

	// add the channel to the path's list of channels
	LIST_INSERT_HEAD(&(path->channel_list), channel, path_entries);

	*new_channel = channel;

	xspd_info(10, "%s: allocated new channel of size: %d", path->description, channel->bandwidth);

	return 0;

error_exit_reservation:
	if (oscars_close_path(pi->java_binary, pi->axis_path, pi->url, pi->client_dir, reservation_id, &error_msg) != 0) {
		xspd_event("oscars.circuit.close.failed", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, size, error_msg);
		xspd_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
	}
    pi->status = OSCARS_DOWN;
error_exit_channel:
	xspd_free_channel(channel);
error_exit:
	return -1;
}

static int __xspd_oscars_shared_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg) {
	*ret_error_msg = strdup("channel resizing not supported");
	xspd_err(0, "channel resizing not supported");
	return -1;
}

static int __xspd_oscars_shared_close_channel(xspdPath *path, xspdChannel *channel) {
	xspdOSCARSPath *pi = path->path_private;
	xspdChannel *curr_channel;

	xspd_info(0, "%s: shutting down channel", path->description);

	// verify that the channel past is actually in the given path
	for(curr_channel = path->channel_list.lh_first; curr_channel != NULL; curr_channel = curr_channel->path_entries.le_next) {
		if (curr_channel == channel)
			break;
	}

	// if not, error out
	if (curr_channel == NULL) {
		xspd_err(0, "%s: tried to close a channel from a different path", path->description);
		goto error_exit;
	}

	// remove the channel from the list of channels
	LIST_REMOVE(channel, path_entries);

	pi->bandwidth_used -= channel->bandwidth;

	// if we have removed the last channel, close the path down
	if (path->channel_list.lh_first == NULL) {
		char *error_msg;
		xspd_info(10, "%s: no more channels, shutting down path", path->description);

		xspdOSCARSTimeoutArgs *args = xspd_alloc_oscars_timeout_args();
		if (!args) {
			if (oscars_close_path(pi->java_binary, pi->axis_path, pi->url, pi->client_dir, pi->reservation_id, &error_msg) != 0) {
				xspd_warn(0, "__xspd_oscars_shared_close_channel(%s): failed to close path: %s", path->description, error_msg);
				xspd_event("oscars.circuit.close.failed", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, error_msg);
			} else {
				xspd_info(10, "%s: successfully shutdown path", path->description);
				xspd_event("oscars.circuit.close.failed", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, error_msg);
			}
			
			time(&(pi->shutdown_time));
			
			xspd_oscars_reset_path_info(pi);
		} else {
			args->tag = path->tag;
			args->path = path;
			args->timeout = pi->teardown_timeout;
			xspd_tpool_exec(xspd_timeout_handler, args);
		}

	}

	// remove all the connections from the channel list (though, they should be gone already... hrmmm...)
	if (channel->connlist.lh_first != NULL) {
		xspd_warn(0, "__xspd_oscars_shared_close_channel(%s): closing channel with outstanding connections", path->description);

		while(channel->connlist.lh_first != NULL) {
			xspdConn *conn = channel->connlist.lh_first;

			conn->channel = NULL;
			LIST_REMOVE(conn, channel_entries);
		}
	}

	xspd_free_channel(channel);

	xspd_info(10, "%s: successfully shutdown channel", path->description);

	return 0;

error_exit:
	return -1;
}

static void xspd_timeout_handler(void *arg) {
	xspdOSCARSTimeoutArgs *args = arg;
	xspdPath *path = args->path;
	int tag = args->tag;
	int timeout = args->timeout;
	xspdOSCARSPath *pi = path->path_private;
	char *error_msg;

	pthread_mutex_lock(&(path->lock));

	xspd_info(8, "Sleeping for %d seconds", timeout);
	// we have the tag check in here to make sure nothing changed between
	// when the closing thread launched us and when we were able to lock
	// the path structure.
	if (path->tag == tag) {
		int n;
		struct timespec ts;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec + timeout;
		ts.tv_nsec = tv.tv_usec * 1000;

		n = pthread_cond_timedwait(&(path->timeout_cond), &(path->lock), &ts);

		xspd_debug(8, "Timeout handler kicked in");
		if (n == ETIMEDOUT) {
			xspd_debug(8, "A timeout occurred: closing path");

			if (oscars_close_path(pi->java_binary, pi->axis_path, pi->url, pi->client_dir, pi->reservation_id, &error_msg) != 0) {
				xspd_warn(0, "__xspd_oscars_shared_close_channel(%s): failed to close path: %s", path->description, error_msg);
				xspd_event("oscars.circuit.close.failed", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, error_msg);
			} else {
				xspd_info(10, "%s: successfully shutdown path", path->description);
				xspd_event("oscars.circuit.close.failed", path, "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"", pi->src, pi->dst, pi->url, pi->vlan_id, error_msg);
			}

            time(&(pi->shutdown_time));

			xspd_oscars_reset_path_info(pi);
		}
	}

	pthread_mutex_unlock(&(path->lock));
}

static void xspd_oscars_reset_path_info(xspdOSCARSPath *pi) {
	if (pi->reservation_id)
		free(pi->reservation_id);
	pi->reservation_id = NULL;
	pi->bandwidth_used = 0;
	pi->bandwidth = 0;
	pi->status = OSCARS_DOWN;
}

static xspdOSCARSTimeoutArgs *xspd_alloc_oscars_timeout_args() {
	xspdOSCARSTimeoutArgs *args;

	args = malloc(sizeof(xspdOSCARSTimeoutArgs));
	if (!args) {
		goto error_exit;
	}

	bzero(args, sizeof(xspdOSCARSTimeoutArgs));

	return args;

error_exit:
	return NULL;
}

static xspdOSCARSPath *xspd_alloc_oscars_path() {
	xspdOSCARSPath *pi ;

	pi = malloc(sizeof(xspdOSCARSPath));
	if (!pi) {
		goto error_exit;
	}

	bzero(pi, sizeof(xspdOSCARSPath));

	if (pthread_cond_init(&(pi->setup_cond), NULL) != 0)
		goto error_exit_path;

	return pi;

error_exit_path:
    free(pi);
error_exit:
	return NULL;
}

static void xspd_free_oscars_path(xspdOSCARSPath *pi) {
	if (pi->url)
		free(pi->url);
	if (pi->client_dir)
		free(pi->client_dir);
	if (pi->src)
		free(pi->src);
	if (pi->dst)
		free(pi->dst);
	if (pi->java_binary)
		free(pi->java_binary);
	if (pi->axis_path)
		free(pi->axis_path);
	if (pi->reservation_id)
		free(pi->reservation_id);
	free(pi);
}

static void xspd_oscars_shared_free_path(xspdPath *path) {
	xspd_free_oscars_path((xspdOSCARSPath *) path->path_private);
	xspd_free_path(path);
}

#if 0

static int xspd_oscars_request_path(const char *oscars_server, int oscars_port, const char *request_file, uint32_t size, char **ret_reservation_id, xmlDoc **reservation_resp, uint32_t *new_bandwidth) {
	char tmp[255];
	char buf[2048];
	int sd;
	int amt_recvd;
	xmlDocPtr req_doc, resp_doc;
	xmlNodePtr root;
	char *ast_status;
	char *reservation_id;
	int n;
	uint32_t bandwidth;
	xmlChar *xml_buf;
	int xml_buf_size;
	int amt_sent;
	struct timeval stime, etime;

	gettimeofday(&stime, NULL);

	req_doc = xmlParseFile(request_file);
	if (!req_doc) {
		xspd_err(0, "error parsing request file %s", request_file);
		goto error_exit;
	}

	root = xmlDocGetRootElement(req_doc);
	if (!root) {
		xspd_err(0, "invalid XML document in file %s: no root element", request_file);
		goto error_exit_req_doc;
	}

	if (size != 0) {
		if (oscars_set_bandwidth(root, size) != 0) {
			xspd_warn(0, "couldn't set the requested bandwidth to %d", size);
		}
	}

	xmlDocDumpFormatMemory(req_doc, &xml_buf, &xml_buf_size, 0);

	snprintf(tmp, 255, "%s/%d", oscars_server, oscars_port);

	sd = lsl_make_connection(tmp);
	if (sd < 0) {
		xspd_err(0, "couldn't connect to %s/%d", oscars_server, oscars_port);
		goto error_exit_xml_buf;
	}

	xspd_info(10, "sending request: \"%s\"", xml_buf);

	amt_sent = 0;
	do {
		n = send(sd, xml_buf + amt_sent, xml_buf_size - amt_sent, 0);
		if (n <= 0) {
			xspd_err(0, "failed to send ASTB request to %s/%d", oscars_server, oscars_port);
			goto error_exit_sd;
		}

		amt_sent += n;
	} while (amt_sent < xml_buf_size);

	bzero(buf, sizeof(buf));

	amt_recvd = 0;

	do {
		n = recv(sd, buf + amt_recvd, sizeof(buf) - amt_recvd, 0);
		if (n < 0) {
			xspd_err(0, "failed to receive ASTB response from %s/%d", oscars_server, oscars_port);
			goto error_exit_sd;
		}

		amt_recvd += n;
	} while(n > 0);

	if (amt_recvd == 0)
		goto error_exit_sd;

	xspd_info(10, "response received: \"%s\"", buf);

	resp_doc = xmlParseMemory(buf, strlen(buf));
	if (!resp_doc) {
		xspd_err(0, "malformed XML document received");
		goto error_exit_sd;
	}

	root = xmlDocGetRootElement(resp_doc);
	if (!root) {
		xspd_err(0, "invalid XML document received: no root element");
		goto error_exit_resp_doc;
	}

	ast_status = oscars_get_status(root);
	if (!ast_status) {
		xspd_err(0, "invalid XML document received: no status element");
		goto error_exit_resp_doc;
	}

	if (strcmp(ast_status, "AST_SUCCESS") != 0) {
		xspd_err(0, "ASTB path setup failed");
		goto error_exit_status;
	}

	reservation_id = oscars_get_ast_id(root);
	if (!reservation_id) {
		xspd_err(0, "invalid XML document received: no ast id");
		goto error_exit_status;
	}

	if (oscars_get_bandwidth(root, &bandwidth) != 0) {
		xspd_err(0, "invalid XML document received: no bandwidth");
		goto error_exit_id;
	}

	xspd_info(0, "reservation: %s size: %d Mbit/s", reservation_id, bandwidth);

	*ret_reservation_id = reservation_id;
	*new_bandwidth = bandwidth;

	close(sd);
	free(ast_status);
	xmlFree(xml_buf);
	xmlFreeDoc(req_doc);

	gettimeofday(&etime, NULL);

	xspd_info(0, "time to allocate path: %f", difftv(&stime, &etime));

	return 0;

error_exit_id:
	free(reservation_id);
error_exit_status:
	free(ast_status);
error_exit_resp_doc:
	xmlFreeDoc(resp_doc);
error_exit_sd:
	close(sd);
error_exit_xml_buf:
	xmlFree(xml_buf);
error_exit_req_doc:
	xmlFreeDoc(req_doc);
error_exit:
	return -1;
}

static int xspd_oscars_resize_path(const char *oscars_server, int oscars_port, const char *request_file, const char *reservation_id, uint32_t old_size, uint32_t new_size, char **ret_reservation_id, xmlDoc **reservation_resp, uint32_t *new_bandwidth) {
	struct timeval stime, etime;

	gettimeofday(&stime, NULL);

	if (xspd_oscars_close_path(oscars_server, oscars_port, reservation_id) != 0) {
		xspd_err(0, "couldn't close existing path");
		goto error_exit;
	}

	if (xspd_oscars_request_path(oscars_server, oscars_port, request_file, new_size, ret_reservation_id, reservation_resp, new_bandwidth) != 0) {
		xspd_err(0, "couldn't open path with new size");
		goto error_exit_path;
	}

	gettimeofday(&etime, NULL);

	xspd_info(0, "time to resize: %f", difftv(&stime, &etime));

	return 0;

error_exit_path:
	if (xspd_oscars_request_path(oscars_server, oscars_port, request_file, old_size, ret_reservation_id, reservation_resp, new_bandwidth) != 0) {
		xspd_err(0, "closed existing path, couldn't recreate it. You didn't *need* that path did you...");
	}
error_exit:
	return -1;
}

static int xspd_oscars_close_path(const char *oscars_server, int oscars_port, const char *reservation_id) {
	int sd, n;
	char buf[1024];
	char tmp[255];
	int amt_recvd;
	xmlDocPtr doc;
	xmlNodePtr root;
	char *ast_status;
	struct timeval stime, etime;

	gettimeofday(&stime, NULL);

	snprintf(tmp, 255, "%s/%d", oscars_server, oscars_port);
	sd = lsl_make_connection(tmp);
	if (sd < 0) {
		xspd_err(0, "couldn't connect to %s/%d", oscars_server, oscars_port);
		goto error_exit;
	}

	snprintf(buf, sizeof(buf), "<topology action=\"RELEASE_REQ\" ast_id=\"%s\" />", reservation_id);

	xspd_info(10, "sending: \"%s\"", buf);

	n = send(sd, buf, strlen(buf), 0);
	if (n < strlen(buf)) {
		xspd_err(0, "couldn't send tear down message");
		goto error_exit_sd;
	}

	bzero(buf, sizeof(buf));

	amt_recvd = 0;

	do {
		n = recv(sd, buf + amt_recvd, sizeof(buf) - amt_recvd, 0);
		if (n > 0) {
			amt_recvd += n;
		}
	} while(n > 0);

	xspd_info(10, "received: \"%s\"", buf);

	doc = xmlParseMemory(buf, strlen(buf));
	if (!doc) {
		xspd_err(0, "malformed response received");
		goto error_exit_sd;
	}

	root = xmlDocGetRootElement(doc);
	if (!root) {
		xspd_err(0, "invalid response received: no root element");
		goto error_exit_doc;
	}

	ast_status = oscars_get_status(root);
	if (!ast_status) {
		xspd_err(0, "invalid response received: no status element");
		goto error_exit_doc;
	}

	if (strcmp(ast_status, "AST_SUCCESS") != 0) {
		xspd_err(0, "ASTB path teardown failed");
		goto error_exit_status;
	}

	close(sd);
	xmlFreeDoc(doc);
	xmlFree(ast_status);

	gettimeofday(&etime, NULL);

	xspd_info(0, "time to shutdown path: %f", difftv(&stime, &etime));

	return 0;

error_exit_status:
	xmlFree(ast_status);
error_exit_doc:
	xmlFreeDoc(doc);
error_exit_sd:
	close(sd);
error_exit:
	return -1;
}

#endif


