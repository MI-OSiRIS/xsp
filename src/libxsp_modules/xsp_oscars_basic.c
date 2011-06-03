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

#include "xsp_oscars_basic.h"

#include "xsp_modules.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_session.h"
#include "xsp_path_handler.h"
#include "hashtable.h"
#include "xsp_config.h"

#ifdef OSCARS5
#include "oscars.nsmap"
#endif

#ifdef OSCARS6
#include "oscars6.nsmap"
#endif

typedef struct xsp_oscars_timeout_args {
	xspPath *path;
	int tag;
	int timeout;
} xspOSCARSTimeoutArgs;

int xsp_oscars_shared_init();
static int xsp_oscars_shared_allocate_path(const xspSettings *settings, xspPath **ret_path, char **ret_error_msg);
static char *xsp_oscars_generate_path_id(const xspSettings *settings, char **ret_error_msg);
static int xsp_oscars_shared_new_channel(xspPath *path, xspNetPathRule *rule, xspChannel **channel, char **ret_error_msg);
static int xsp_oscars_shared_close_channel(xspPath *path, xspChannel *channel);
static int xsp_oscars_shared_resize_channel(xspPath *path, xspChannel *channel, uint32_t new_size, char **ret_error_msg);
static void xsp_oscars_shared_free_path(xspPath *path);

static int __xsp_oscars_shared_new_channel(xspPath *path, uint32_t size, xspChannel **channel, char **ret_error_msg);
static int __xsp_oscars_shared_resize_channel(xspPath *path, xspChannel *channel, uint32_t new_size, char **ret_error_msg);
static int __xsp_oscars_shared_close_channel(xspPath *path, xspChannel *channel);

static xspOSCARSPath *xsp_alloc_oscars_path();
static void xsp_free_oscars_path(xspOSCARSPath *pi);
static void xsp_oscars_reset_path_info();

static xspOSCARSTimeoutArgs *xsp_alloc_oscars_timeout_args();
static void xsp_timeout_handler(void *arg);

xspModule xsp_oscars_shared_module = {
	.desc = "OSCARS Module",
	.dependencies = "",
	.init = xsp_oscars_shared_init
};

xspPathHandler xsp_oscars_shared_path_handler = {
	.name = "OSCARS",
	.allocate = xsp_oscars_shared_allocate_path,
	.get_path_id = xsp_oscars_generate_path_id,
};

xspModule *module_info() {
	return &xsp_oscars_shared_module;
}

int xsp_oscars_shared_init() {
	return xsp_add_path_handler(&xsp_oscars_shared_path_handler);
}

static char *xsp_oscars_generate_path_id(const xspSettings *settings, char **ret_error_msg) {
	char *oscars_server;
	char *oscars_src_id;
	char *oscars_dst_id;
	char *oscars_vlan_id;
	char *path_id;

	if (xsp_settings_get_2(settings, "oscars", "server", &oscars_server) != 0) {
		if (ret_error_msg) {
			xsp_err(0, "No OSCARS server specified");
			*ret_error_msg = strdup("No OSCARS server specified");
		}

		goto error_exit;
	}

	if (xsp_settings_get_2(settings, "oscars", "src_id", &oscars_src_id) != 0) {
		if (ret_error_msg) {
			xsp_err(0, "No OSCARS source identifier specified");
			*ret_error_msg = strdup("No OSCARS source identifier specified");
		}

		goto error_exit;
	}

	if (xsp_settings_get_2(settings, "oscars", "dst_id", &oscars_dst_id) != 0) {
		if (ret_error_msg) {
			xsp_err(0, "No OSCARS destination identifier specified");
			*ret_error_msg = strdup("No OSCARS destination identifier specified");
		}

		goto error_exit;
	}

	if (xsp_settings_get_2(settings, "oscars", "vlan_id", &oscars_vlan_id) != 0) {
		oscars_vlan_id = "N/A";
	}

	if (strcmp(oscars_src_id, oscars_dst_id) > 0) {
		char *tmp = oscars_src_id;
		oscars_src_id = oscars_dst_id;
		oscars_dst_id = tmp;
	}

	if (xsp_settings_get_2(settings, "oscars", "path_id", &path_id) != 0) {
		if (ret_error_msg) {
			if (asprintf(&path_id, "%s->%s@%s:%s", oscars_src_id,
				     oscars_dst_id, oscars_server, oscars_vlan_id) <= 0) {
				goto error_exit;
			}
		}
	}

	return path_id;

error_exit:
	*ret_error_msg = strdup("ERROR");
	return NULL;
}

static int xsp_oscars_shared_allocate_path(const xspSettings *settings, xspPath **ret_path, char **ret_error_msg) {
	xspPath *path;
	xspOSCARSPath *pi;
	char *oscars_server;
	char *oscars_src_id;
	char *oscars_dst_id;
	int oscars_src_tagged;
	int oscars_dst_tagged;
	int oscars_duration;
	char *oscars_vlan_id;
	int oscars_sleep_time;
	int oscars_clock_offset;
	int oscars_teardown_timeout;
	int oscars_intercircuit_pause_time;
	char *path_type_str;
	int path_type;
	int bandwidth;
	char *wsse_keyfile;
	char *wsse_keypass;
	char *wsse_certfile;
	char *mon_server;
	
	
	if (xsp_settings_get_2(settings, "oscars", "server", &oscars_server) != 0) {
		xsp_err(0, "No OSCARS server specified");
		goto error_exit;
	}
	
	if (xsp_settings_get_2(settings, "oscars", "monitor", &mon_server) != 0) {
                xsp_warn(0, "No OSCARS monitor server specified");
                mon_server = NULL;
        }
	
        if (xsp_settings_get_2(settings, "oscars", "wsse_keyfile", &wsse_keyfile) != 0) {
                xsp_err(0, "No OSCARS WS-Sec key specified");
                goto error_exit;
        }

        if (xsp_settings_get_2(settings, "oscars", "wsse_keypass", &wsse_keypass) != 0) {
                xsp_warn(0, "No OSCARS WS-Sec key password specified");
		wsse_keypass = NULL;
        }

        if (xsp_settings_get_2(settings, "oscars", "wsse_certfile", &wsse_certfile) != 0) {
                xsp_err(0, "No OSCARS WS-Sec cert specified");
                goto error_exit;
        }

	if (xsp_settings_get_int_2(settings, "oscars", "duration", &oscars_duration) != 0) {
		xsp_err(0, "No duration specified for OSCARS reservation");
		goto error_exit;
	}

	if (xsp_settings_get_2(settings, "oscars", "src_id", &oscars_src_id) != 0) {
		xsp_err(0, "No OSCARS source identifier specified");
		goto error_exit;
	}
	
	if (xsp_settings_get_2(settings, "oscars", "dst_id", &oscars_dst_id) != 0) {
		xsp_err(0, "No OSCARS destination identifier specified");
		goto error_exit;
	}
	
	if (xsp_settings_get_2(settings, "oscars", "type", &path_type_str) != 0) {
		path_type_str = "shared";
	}

	if (xsp_settings_get_int_2(settings, "oscars", "bandwidth", &bandwidth) != 0) {
		bandwidth = 0;
        }
	
	if (strcmp(path_type_str, "private") == 0) {
		xsp_info(0, "Using private path");
		path_type = PATH_PRIVATE;
	} else if (strcmp(path_type_str, "shared") == 0) {
		path_type = PATH_SHARED;
		xsp_info(0, "Using shared path");
	} else {
		xsp_err(0, "Invalid path type. must be 'private' or 'shared'");
		goto error_exit;
	}

	if (xsp_settings_get_2(settings, "oscars", "vlan_id", &oscars_vlan_id) != 0) {
		oscars_vlan_id = NULL;
	}
	
	if (xsp_settings_get_int_2(settings, "oscars", "clock_offset", &oscars_clock_offset) != 0) {
		oscars_clock_offset = 0;
	}

	if (xsp_settings_get_int_2(settings, "oscars", "teardown_timeout", &oscars_teardown_timeout) != 0) {
		oscars_teardown_timeout = 0;
	}

	if (xsp_settings_get_int_2(settings, "oscars", "intercircuit_pause_time", &oscars_intercircuit_pause_time) != 0) {
		oscars_intercircuit_pause_time = 0;
	}

	if (xsp_settings_get_int_2(settings, "oscars", "sleep_time", &oscars_sleep_time) != 0) {
		oscars_sleep_time = 5;
	}
	
	if (xsp_settings_get_bool_2(settings, "oscars", "src_tagged", &oscars_src_tagged) != 0) {
		oscars_src_tagged = 1;
	}

	if (xsp_settings_get_bool_2(settings, "oscars", "dst_tagged", &oscars_dst_tagged) != 0) {
		oscars_dst_tagged = 1;
	}

	path = xsp_alloc_path();
	if (!path)
		goto error_exit;

	pi = xsp_alloc_oscars_path();
	if (!pi)
		goto error_exit_path;

	pi->osc.wsse_key = wsse_keyfile;
	pi->osc.wsse_pass = wsse_keypass;
	pi->osc.wsse_cert = wsse_certfile;
	
	pi->osc.soap_endpoint = oscars_server;
	pi->osc.soap_action = NULL;
	pi->osc.namespaces = oscars_namespaces;

	pi->src = oscars_src_id;
	pi->src_tagged = oscars_src_tagged;
	pi->dst = oscars_dst_id;
	pi->dst_tagged = oscars_dst_tagged;
	pi->duration = oscars_duration;
	pi->vlan_id = oscars_vlan_id;
	pi->clock_offset = oscars_clock_offset;
	pi->sleep_time = oscars_sleep_time;
	pi->type = path_type;
	pi->bw = bandwidth;
	pi->teardown_timeout = oscars_teardown_timeout;
	pi->intercircuit_pause_time = oscars_intercircuit_pause_time;
	pi->shutdown_time = 0;
	
	path->path_private = pi;
	path->new_channel = xsp_oscars_shared_new_channel;
	path->resize_channel = xsp_oscars_shared_resize_channel;
	path->close_channel = xsp_oscars_shared_close_channel;
	path->free = xsp_oscars_shared_free_path;

	*ret_path = path;

	return 0;

 error_exit_path:
	xsp_free_path(path);
	*ret_error_msg = strdup("path allocate configuration error");
 error_exit:
	return -1;
}

static int xsp_oscars_shared_new_channel(xspPath *path, xspNetPathRule *rule, xspChannel **channel, char **ret_error_msg) {
	int retval;
	char *error_msg = NULL;

	pthread_mutex_lock(&(path->lock));
	{
		retval = __xsp_oscars_shared_new_channel(path, rule->bandwidth, channel, &error_msg);
	}
	pthread_mutex_unlock(&(path->lock));

	if (error_msg)
		*ret_error_msg = error_msg;

	return retval;
}

static int xsp_oscars_shared_close_channel(xspPath *path, xspChannel *channel) {
	int retval;

	pthread_mutex_lock(&(path->lock));
	{
		retval = __xsp_oscars_shared_close_channel(path, channel);
	}
	pthread_mutex_unlock(&(path->lock));

	return retval;
}

static int xsp_oscars_shared_resize_channel(xspPath *path, xspChannel *channel, uint32_t new_size, char **ret_error_msg) {
	int retval;
	char *error_msg = NULL;

	pthread_mutex_lock(&(path->lock));
	{
		retval = __xsp_oscars_shared_resize_channel(path, channel, new_size, &error_msg);
	}
	pthread_mutex_unlock(&(path->lock));

	if (error_msg)
		*ret_error_msg = error_msg;

	return retval;
}

static int __xsp_oscars_shared_new_channel(xspPath *path, uint32_t size, xspChannel **channel, char **ret_error_msg) {
	char *reservation_id;
	xspOSCARSPath *pi = path->path_private;
	xspChannel *new_channel;
	uint32_t new_bandwidth = size;
	char *error_msg;
	void *response;
	char *status;
	int active = 0;

	path->tag++;
	pthread_cond_signal(&(path->timeout_cond));

	if (xsp_start_soap_ssl(&(pi->osc), SOAP_SSL_NO_AUTHENTICATION) != 0) {
                xsp_err(0, "couldn't start SOAP context");
                goto error_exit;
        }
	
	if (pi->bw > 0)
		new_bandwidth = pi->bw;

	xsp_info(10, "%s: allocating new channel of size: %d", path->description, new_bandwidth);

	new_channel = xsp_alloc_channel();
	if (!new_channel) {
		xsp_err(0, "%s: couldn't allocate channel object", path->description);
		goto error_exit;
	}
	
	if (pi->intercircuit_pause_time > 0) {
		time_t curr_time;
		
		time(&curr_time);
		
		if (curr_time < (pi->shutdown_time + pi->intercircuit_pause_time)) {
			xsp_info(5, "%s: sleeping for %d seconds waiting for the circuit to become available",
				  path->description, ((pi->shutdown_time + pi->intercircuit_pause_time) - curr_time));
			sleep((pi->shutdown_time + pi->intercircuit_pause_time) - curr_time);
		}
	}
	
	while (pi->status == OSCARS_STARTING) {
		pthread_cond_wait(&(pi->setup_cond), &(path->lock));
	}

	if (pi->status == OSCARS_DOWN) {
		time_t stime, etime;
		OSCARS_resRequest create_req;
		OSCARS_pathInfo path_info;
		OSCARS_L2Info l2_info;
		OSCARS_vlanTag l2_stag;
		OSCARS_vlanTag l2_dtag;
		
		pi->status = OSCARS_STARTING;		
		
		time(&stime);	
		stime += pi->clock_offset;
		etime = stime + pi->duration;
		
		xsp_info(0, "%s: the OSCARS path is down, allocating a new one", path->description);
		
		l2_info.src_endpoint = pi->src;
		l2_info.dst_endpoint = pi->dst;
		l2_info.src_vlan = NULL;
		l2_info.dst_vlan = NULL;
		
		if (pi->src_tagged) {
			l2_stag.id = pi->vlan_id;
			l2_stag.tagged = (enum boolean_*)&(pi->src_tagged);
			l2_info.src_vlan = &l2_stag;
		}
		if (pi->dst_tagged) {
			l2_dtag.id = pi->vlan_id;
			l2_dtag.tagged = (enum boolean_*)&(pi->dst_tagged);
			l2_info.dst_vlan = &l2_dtag;
		}
		
		path_info.setup_mode = "timer-automatic";
		path_info.type = NULL;
		path_info.ctrl_plane_path_content = NULL;
		path_info.l2_info = &l2_info;
		path_info.l3_info = NULL;
		path_info.mpls_info = NULL;

		create_req.res_id = NULL;
		create_req.start_time = (int64_t)stime;
		create_req.end_time = (int64_t)etime;
		create_req.bandwidth = (int)new_bandwidth;
		create_req.description = "XSP Path";
		create_req.path_info = &path_info;

		if (oscars_createReservation(&(pi->osc), &create_req, &response) != 0) {
			pthread_cond_signal(&(pi->setup_cond));
			pi->status = OSCARS_DOWN;
			error_msg = strdup("OSCARS RESERVE FAIL");
			//xsp_event("oscars.circuit.reserve.failure", path,
			//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
			//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
			xsp_err(0, "%s: couldn't reserve OSCARS path: %s", path->description, error_msg);
			*ret_error_msg = error_msg;
			goto error_exit_channel;
		}
		
		reservation_id = ((struct ns1__createReply*)response)->globalReservationId;

		xsp_info(10, "Sleeping for %d seconds", pi->sleep_time);
		sleep(pi->sleep_time);
		
	       	while (!active) {
			if (oscars_queryReservation(&(pi->osc), reservation_id, &response) != 0) {
				pthread_cond_signal(&(pi->setup_cond));
				pi->status = OSCARS_DOWN;
				error_msg = strdup("OSCARS QUERY FAIL");
				//xsp_event("oscars.circuit.create.failure", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
				xsp_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
				*ret_error_msg = error_msg;
				goto error_exit_reservation;
			}
			
			status = ((struct ns1__resDetails*)response)->status;
			reservation_id = ((struct ns1__resDetails*)response)->globalReservationId;

			if (strcmp(status,"ACTIVE") == 0){
				active=1;
			}
			
			if (strcmp(status,"FAILED") ==0){
				pthread_cond_signal(&(pi->setup_cond));
				pi->status = OSCARS_DOWN;
				error_msg = strdup("OSCARS STATUS: FAILED");
				//xsp_event("oscars.circuit.create.failure", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
				xsp_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
				*ret_error_msg = error_msg;
				goto error_exit_reservation;
			}
			
			xsp_info(10, "Sleeping for %d seconds", pi->sleep_time);
			sleep(pi->sleep_time);
		}
		
		//xsp_event("oscars.circuit.allocated", path,
		//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
		//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
		
		xsp_info(10, "Sleeping for %d seconds", pi->sleep_time);
		sleep(pi->sleep_time);
		
		xsp_info(0, "%s: allocated new path of size %d Mbit/s(Start Time: %lu End Time: %lu). Id: %s",
			  path->description, new_bandwidth, (unsigned long) stime, (unsigned long) etime,
			  reservation_id);
		
		// save the path information
		pi->reservation_id = reservation_id;
		pi->bandwidth = new_bandwidth;
		
		pi->status = OSCARS_UP;
		
		pthread_cond_signal(&(path->timeout_cond));
	} else if (pi->type == PATH_SHARED) {
		xsp_info(0, "%s: reusing existing path. Amount used: %d/%d",
			  path->description, pi->bandwidth_used, pi->bandwidth);
	} else {
	      /*
		uint32_t new_bandwidth;

		xsp_info(0, "%s: resizing path from %d to %d", path->description, pi->bandwidth, new_bandwidth);

		// XXX: call oscars_modifyReservation() here

		xsp_info(10, "%s: path resized to %d Mbit/s. New id: %s", path->description, new_bandwidth, reservation_id);

		free(pi->reservation_id);
		pi->reservation_id = reservation_id;
		pi->bandwidth = new_bandwidth;
	      */
		*ret_error_msg = strdup("OSCARS CAN'T SHARE");
		xsp_err(0, "%s: Can't resize paths", path->description);
		goto error_exit_channel;
	}
	
	pi->bandwidth_used += new_bandwidth;
	
	// set the channels bandwidth
	new_channel->bandwidth = new_bandwidth;

	// add the channel to the path's list of channels
	LIST_INSERT_HEAD(&(path->channel_list), new_channel, path_entries);

	*channel = new_channel;
	
	xsp_stop_soap_ssl(&(pi->osc));

	xsp_info(10, "%s: allocated new channel of size: %d", path->description, new_channel->bandwidth);

	return 0;

 error_exit_reservation:
	if (oscars_cancelReservation(&(pi->osc), reservation_id, &response) != 0) {
		//xsp_event("oscars.circuit.close.failed", path,
		//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
		//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
		xsp_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
	}
	pi->status = OSCARS_DOWN;
 error_exit_channel:
	xsp_stop_soap_ssl(&(pi->osc));
	*channel = NULL;
	//xsp_free_channel(new_channel);
 error_exit:
	return -1;
}

static int __xsp_oscars_shared_resize_channel(xspPath *path, xspChannel *channel, uint32_t new_size, char **ret_error_msg) {
	*ret_error_msg = strdup("channel resizing not supported");
	xsp_err(0, "channel resizing not supported");
	return -1;
}

static int __xsp_oscars_shared_close_channel(xspPath *path, xspChannel *channel) {
	xspOSCARSPath *pi = path->path_private;
	xspChannel *curr_channel;

	xsp_info(0, "%s: shutting down channel", path->description);

	// verify that the channel past is actually in the given path
	for(curr_channel = path->channel_list.lh_first; curr_channel != NULL; curr_channel = curr_channel->path_entries.le_next) {
		if (curr_channel == channel)
			break;
	}
	
	// if not, error out
	if (curr_channel == NULL) {
		xsp_err(0, "%s: tried to close a channel from a different path", path->description);
		goto error_exit;
	}

	// remove the channel from the list of channels
	LIST_REMOVE(channel, path_entries);

	pi->bandwidth_used -= channel->bandwidth;

	// if we have removed the last channel, close the path down
	if (path->channel_list.lh_first == NULL) {
		void *response;
		xsp_info(10, "%s: no more channels, shutting down path", path->description);
		
		xspOSCARSTimeoutArgs *args = xsp_alloc_oscars_timeout_args();
		if (!args) {
			
			if (xsp_start_soap_ssl(&(pi->osc), SOAP_SSL_NO_AUTHENTICATION) != 0) {
				xsp_err(0, "couldn't start SOAP context");
				goto error_exit_path;
			}
			
			if (oscars_cancelReservation(&(pi->osc), pi->reservation_id, &response) != 0) {
				xsp_warn(0, "__xsp_oscars_shared_close_channel(%s): failed to close path",
					  path->description);
				//xsp_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			} else {
				xsp_info(10, "%s: successfully shutdown path", path->description);
				//xsp_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			}
			
			time(&(pi->shutdown_time));
			xsp_oscars_reset_path_info(pi);
			xsp_stop_soap_ssl(&(pi->osc));
		} else {
			args->tag = path->tag;
			args->path = path;
			args->timeout = pi->teardown_timeout;
			xsp_tpool_exec(xsp_timeout_handler, args);
		}

	}

	// remove all the connections from the channel list (though, they should be gone already... hrmmm...)
	if (channel->connlist.lh_first != NULL) {
		xsp_warn(0, "__xsp_oscars_shared_close_channel(%s): closing channel with outstanding connections",
			  path->description);

		while(channel->connlist.lh_first != NULL) {
			xspConn *conn = channel->connlist.lh_first;

			conn->channel = NULL;
			LIST_REMOVE(conn, channel_entries);
		}
	}

	xsp_free_channel(channel);

	xsp_info(10, "%s: successfully shutdown channel", path->description);

	return 0;

 error_exit_path:
	xsp_stop_soap_ssl(&(pi->osc));
 error_exit:
	return -1;
}

static void xsp_timeout_handler(void *arg) {
	xspOSCARSTimeoutArgs *args = arg;
	xspPath *path = args->path;
	int tag = args->tag;
	int timeout = args->timeout;
	xspOSCARSPath *pi = path->path_private;
	char *error_msg;
	void *response;

	pthread_mutex_lock(&(path->lock));

	xsp_info(8, "Sleeping for %d seconds", timeout);
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

		xsp_debug(8, "Timeout handler kicked in");
		if (n == ETIMEDOUT) {
			xsp_debug(8, "A timeout occurred: closing path");
			
			if (xsp_start_soap_ssl(&(pi->osc), SOAP_SSL_NO_AUTHENTICATION) != 0) {
                                xsp_err(0, "couldn't start SOAP context");
                                goto error_exit_path;
                        }

                        if (oscars_cancelReservation(&(pi->osc), pi->reservation_id, &response) != 0) {
				xsp_warn(0, "__xsp_oscars_shared_close_channel(%s): failed to close path",
					  path->description);
				//xsp_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			} else {
				xsp_info(10, "%s: successfully shutdown path", path->description);
				//xsp_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			}
			time(&(pi->shutdown_time));
			xsp_oscars_reset_path_info(pi);
			xsp_stop_soap_ssl(&(pi->osc));
		}
	}
	pthread_mutex_unlock(&(path->lock));

 error_exit_path:
	xsp_stop_soap_ssl(&(pi->osc));
}

static void xsp_oscars_reset_path_info(xspOSCARSPath *pi) {
	pi->reservation_id = NULL;
	pi->bandwidth_used = 0;
	pi->bandwidth = 0;
	pi->status = OSCARS_DOWN;
}

static xspOSCARSTimeoutArgs *xsp_alloc_oscars_timeout_args() {
	xspOSCARSTimeoutArgs *args;

	args = malloc(sizeof(xspOSCARSTimeoutArgs));
	if (!args) {
		goto error_exit;
	}

	bzero(args, sizeof(xspOSCARSTimeoutArgs));

	return args;

error_exit:
	return NULL;
}

static xspOSCARSPath *xsp_alloc_oscars_path() {
	xspOSCARSPath *pi ;

	pi = malloc(sizeof(xspOSCARSPath));
	if (!pi) {
		goto error_exit;
	}

	bzero(pi, sizeof(xspOSCARSPath));

	if (pthread_cond_init(&(pi->setup_cond), NULL) != 0)
		goto error_exit_path;

	return pi;

error_exit_path:
    free(pi);
error_exit:
	return NULL;
}

static void xsp_free_oscars_path(xspOSCARSPath *pi) {
	if (pi->src)
		free(pi->src);
	if (pi->dst)
		free(pi->dst);
	free(pi);
}

static void xsp_oscars_shared_free_path(xspPath *path) {
	xsp_free_oscars_path((xspOSCARSPath *) path->path_private);
	xsp_free_path(path);
}
