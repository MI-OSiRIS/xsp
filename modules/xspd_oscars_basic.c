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

#ifdef OSCARS5
#include "oscars.nsmap"
#endif

#ifdef OSCARS6
#include "oscars6.nsmap"
#endif

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

static int __xspd_oscars_shared_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg);
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
	char *oscars_vlan_id;
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

	if (xspd_settings_get_2(settings, "oscars", "vlan_id", &oscars_vlan_id) != 0) {
		oscars_vlan_id = "N/A";
	}

	if (strcmp(oscars_src_id, oscars_dst_id) > 0) {
		char *tmp = oscars_src_id;
		oscars_src_id = oscars_dst_id;
		oscars_dst_id = tmp;
	}

	if (xspd_settings_get_2(settings, "oscars", "path_id", &path_id) != 0) {
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

static int xspd_oscars_shared_allocate_path(const xspdSettings *settings, xspdPath **ret_path, char **ret_error_msg) {
	xspdPath *path;
	xspdOSCARSPath *pi;
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
	
	
	if (xspd_settings_get_2(settings, "oscars", "server", &oscars_server) != 0) {
		xspd_err(0, "No OSCARS server specified");
		goto error_exit;
	}
	
	if (xspd_settings_get_2(settings, "oscars", "monitor", &mon_server) != 0) {
                xspd_warn(0, "No OSCARS monitor server specified");
                mon_server = NULL;
        }
	
        if (xspd_settings_get_2(settings, "oscars", "wsse_keyfile", &wsse_keyfile) != 0) {
                xspd_err(0, "No OSCARS WS-Sec key specified");
                goto error_exit;
        }

        if (xspd_settings_get_2(settings, "oscars", "wsse_keypass", &wsse_keypass) != 0) {
                xspd_warn(0, "No OSCARS WS-Sec key password specified");
		wsse_keypass = NULL;
        }

        if (xspd_settings_get_2(settings, "oscars", "wsse_certfile", &wsse_certfile) != 0) {
                xspd_err(0, "No OSCARS WS-Sec cert specified");
                goto error_exit;
        }

	if (xspd_settings_get_int_2(settings, "oscars", "duration", &oscars_duration) != 0) {
		xspd_err(0, "No duration specified for OSCARS reservation");
		goto error_exit;
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
		path_type_str = "shared";
	}

	if (xspd_settings_get_int_2(settings, "oscars", "bandwidth", &bandwidth) != 0) {
		bandwidth = 0;
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

	if (xspd_settings_get_2(settings, "oscars", "vlan_id", &oscars_vlan_id) != 0) {
		oscars_vlan_id = NULL;
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
	path->new_channel = xspd_oscars_shared_new_channel;
	path->resize_channel = xspd_oscars_shared_resize_channel;
	path->close_channel = xspd_oscars_shared_close_channel;
	path->free = xspd_oscars_shared_free_path;

	*ret_path = path;

	return 0;

 error_exit_path:
	xspd_free_path(path);
	*ret_error_msg = strdup("path allocate configuration error");
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

static int __xspd_oscars_shared_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg) {
	char *reservation_id;
	xspdOSCARSPath *pi = path->path_private;
	xspdChannel *new_channel;
	uint32_t new_bandwidth = size;
	char *error_msg;
	void *response;
	char *status;
	int active = 0;

	path->tag++;
	pthread_cond_signal(&(path->timeout_cond));

	if (xspd_start_soap_ssl(&(pi->osc), SOAP_SSL_NO_AUTHENTICATION) != 0) {
                xspd_err(0, "couldn't start SOAP context");
                goto error_exit;
        }
	
	if (pi->bw > 0)
		new_bandwidth = pi->bw;

	xspd_info(10, "%s: allocating new channel of size: %d", path->description, new_bandwidth);

	new_channel = xspd_alloc_channel();
	if (!new_channel) {
		xspd_err(0, "%s: couldn't allocate channel object", path->description);
		goto error_exit;
	}
	
	if (pi->intercircuit_pause_time > 0) {
		time_t curr_time;
		
		time(&curr_time);
		
		if (curr_time < (pi->shutdown_time + pi->intercircuit_pause_time)) {
			xspd_info(5, "%s: sleeping for %d seconds waiting for the circuit to become available",
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
		
		xspd_info(0, "%s: the OSCARS path is down, allocating a new one", path->description);
		
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
		create_req.description = "XSPD Path";
		create_req.path_info = &path_info;

		if (oscars_createReservation(&(pi->osc), &create_req, &response) != 0) {
			pthread_cond_signal(&(pi->setup_cond));
			pi->status = OSCARS_DOWN;
			error_msg = strdup("OSCARS RESERVE FAIL");
			//xspd_event("oscars.circuit.reserve.failure", path,
			//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
			//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
			xspd_err(0, "%s: couldn't reserve OSCARS path: %s", path->description, error_msg);
			*ret_error_msg = error_msg;
			goto error_exit_channel;
		}
		
		reservation_id = ((struct ns1__createReply*)response)->globalReservationId;

		xspd_info(10, "Sleeping for %d seconds", pi->sleep_time);
		sleep(pi->sleep_time);
		
	       	while (!active) {
			if (oscars_queryReservation(&(pi->osc), reservation_id, &response) != 0) {
				pthread_cond_signal(&(pi->setup_cond));
				pi->status = OSCARS_DOWN;
				error_msg = strdup("OSCARS QUERY FAIL");
				//xspd_event("oscars.circuit.create.failure", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
				xspd_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
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
				//xspd_event("oscars.circuit.create.failure", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
				xspd_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
				*ret_error_msg = error_msg;
				goto error_exit_reservation;
			}
			
			xspd_info(10, "Sleeping for %d seconds", pi->sleep_time);
			sleep(pi->sleep_time);
		}
		
		//xspd_event("oscars.circuit.allocated", path,
		//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
		//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
		
		xspd_info(10, "Sleeping for %d seconds", pi->sleep_time);
		sleep(pi->sleep_time);
		
		xspd_info(0, "%s: allocated new path of size %d Mbit/s(Start Time: %lu End Time: %lu). Id: %s",
			  path->description, new_bandwidth, (unsigned long) stime, (unsigned long) etime,
			  reservation_id);
		
		// save the path information
		pi->reservation_id = reservation_id;
		pi->bandwidth = new_bandwidth;
		
		pi->status = OSCARS_UP;
		
		pthread_cond_signal(&(path->timeout_cond));
	} else if (pi->type == PATH_SHARED) {
		xspd_info(0, "%s: reusing existing path. Amount used: %d/%d",
			  path->description, pi->bandwidth_used, pi->bandwidth);
	} else {
	      /*
		uint32_t new_bandwidth;

		xspd_info(0, "%s: resizing path from %d to %d", path->description, pi->bandwidth, new_bandwidth);

		// XXX: call oscars_modifyReservation() here

		xspd_info(10, "%s: path resized to %d Mbit/s. New id: %s", path->description, new_bandwidth, reservation_id);

		free(pi->reservation_id);
		pi->reservation_id = reservation_id;
		pi->bandwidth = new_bandwidth;
	      */
		*ret_error_msg = strdup("OSCARS CAN'T SHARE");
		xspd_err(0, "%s: Can't resize paths", path->description);
		goto error_exit_channel;
	}
	
	pi->bandwidth_used += new_bandwidth;
	
	// set the channels bandwidth
	new_channel->bandwidth = new_bandwidth;

	// add the channel to the path's list of channels
	LIST_INSERT_HEAD(&(path->channel_list), new_channel, path_entries);

	*channel = new_channel;
	
	xspd_stop_soap_ssl(&(pi->osc));

	xspd_info(10, "%s: allocated new channel of size: %d", path->description, new_channel->bandwidth);

	return 0;

 error_exit_reservation:
	if (oscars_cancelReservation(&(pi->osc), reservation_id, &response) != 0) {
		//xspd_event("oscars.circuit.close.failed", path,
		//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
		//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
		xspd_err(0, "%s: couldn't create OSCARS path: %s", path->description, error_msg);
	}
	pi->status = OSCARS_DOWN;
 error_exit_channel:
	xspd_stop_soap_ssl(&(pi->osc));
	*channel = NULL;
	//xspd_free_channel(new_channel);
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
		void *response;
		xspd_info(10, "%s: no more channels, shutting down path", path->description);
		
		xspdOSCARSTimeoutArgs *args = xspd_alloc_oscars_timeout_args();
		if (!args) {
			
			if (xspd_start_soap_ssl(&(pi->osc), SOAP_SSL_NO_AUTHENTICATION) != 0) {
				xspd_err(0, "couldn't start SOAP context");
				goto error_exit_path;
			}
			
			if (oscars_cancelReservation(&(pi->osc), pi->reservation_id, &response) != 0) {
				xspd_warn(0, "__xspd_oscars_shared_close_channel(%s): failed to close path",
					  path->description);
				//xspd_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			} else {
				xspd_info(10, "%s: successfully shutdown path", path->description);
				//xspd_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			}
			
			time(&(pi->shutdown_time));
			xspd_oscars_reset_path_info(pi);
			xspd_stop_soap_ssl(&(pi->osc));
		} else {
			args->tag = path->tag;
			args->path = path;
			args->timeout = pi->teardown_timeout;
			xspd_tpool_exec(xspd_timeout_handler, args);
		}

	}

	// remove all the connections from the channel list (though, they should be gone already... hrmmm...)
	if (channel->connlist.lh_first != NULL) {
		xspd_warn(0, "__xspd_oscars_shared_close_channel(%s): closing channel with outstanding connections",
			  path->description);

		while(channel->connlist.lh_first != NULL) {
			xspdConn *conn = channel->connlist.lh_first;

			conn->channel = NULL;
			LIST_REMOVE(conn, channel_entries);
		}
	}

	xspd_free_channel(channel);

	xspd_info(10, "%s: successfully shutdown channel", path->description);

	return 0;

 error_exit_path:
	xspd_stop_soap_ssl(&(pi->osc));
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
	void *response;

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
			
			if (xspd_start_soap_ssl(&(pi->osc), SOAP_SSL_NO_AUTHENTICATION) != 0) {
                                xspd_err(0, "couldn't start SOAP context");
                                goto error_exit_path;
                        }

                        if (oscars_cancelReservation(&(pi->osc), pi->reservation_id, &response) != 0) {
				xspd_warn(0, "__xspd_oscars_shared_close_channel(%s): failed to close path",
					  path->description);
				//xspd_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			} else {
				xspd_info(10, "%s: successfully shutdown path", path->description);
				//xspd_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			}
			time(&(pi->shutdown_time));
			xspd_oscars_reset_path_info(pi);
			xspd_stop_soap_ssl(&(pi->osc));
		}
	}
	pthread_mutex_unlock(&(path->lock));

 error_exit_path:
	xspd_stop_soap_ssl(&(pi->osc));
}

static void xspd_oscars_reset_path_info(xspdOSCARSPath *pi) {
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
	if (pi->src)
		free(pi->src);
	if (pi->dst)
		free(pi->dst);
	free(pi);
}

static void xspd_oscars_shared_free_path(xspdPath *path) {
	xspd_free_oscars_path((xspdOSCARSPath *) path->path_private);
	xspd_free_path(path);
}
