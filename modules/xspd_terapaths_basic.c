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

#include "monitoring.h"
#include "terapaths.h"
#include "tps.nsmap"
#include "mntr.nsmap"

#include "xspd_soap_context.h"
#include "xspd_terapaths_basic.h"

#include "xspd_path_handler.h"
#include "xspd_modules.h"
#include "xspd_conn.h"
#include "xspd_logger.h"
#include "xspd_session.h"
#include "hashtable.h"
#include "xspd_config.h"

//typedef struct xspd_terapaths_timeout_args {
//	xspdPath *path;
//	int tag;
//	int timeout;
//} xspdTERAPATHStimeoutArgs;

int xspd_terapaths_init();
void *xspd_terapaths_monitor_path(void *args);
int xspd_terapaths_update_path_status(xspdTERAPATHSPath *pi, xspdSoapContext *msc, xspdSoapContext *tsc, char **status);

// need to figure out where we get parameters from (protocol, settings, combination?
// could have an internal map to match src/dst prefixes with suitable reservation info
static int xspd_terapaths_allocate_path(const xspdSettings *settings, xspdPath **ret_path, char ** ret_error_msg);
static char *xspd_terapaths_generate_path_id(const xspdSettings *settings, char **ret_error_msg);

static int xspd_terapaths_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg);
static int xspd_terapaths_close_channel(xspdPath *path, xspdChannel *channel);
static int xspd_terapaths_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg);
static void xspd_terapaths_free_path(xspdPath *path);

static int __xspd_terapaths_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg);
static int __xspd_terapaths_close_channel(xspdPath *path, xspdChannel *channel);
static int __xspd_terapaths_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg);

static xspdTERAPATHSPath *xspd_alloc_terapaths_path();
static void xspd_free_terapaths_path(xspdTERAPATHSPath *pi);
static void xspd_terapaths_reset_path_info();

static xspdModule xspd_terapaths_module = {
	.desc = "TERAPATHS Module",
	.dependencies = "",
	.init = xspd_terapaths_init
};

// might have to extend the path handler for terapaths, but maybe not
// xspd could just monitor the path and report if/when it goes down
xspdPathHandler xspd_terapaths_path_handler = {
	.name = "TERAPATHS",
	.allocate = xspd_terapaths_allocate_path,
	.get_path_id = xspd_terapaths_generate_path_id,
};

xspdModule *module_info() {
	return &xspd_terapaths_module;
}

// now this just registers TP module as a generic path handler for later use
int xspd_terapaths_init() {
	return xspd_add_path_handler(&xspd_terapaths_path_handler);
}


static int xspd_terapaths_allocate_path(const xspdSettings *settings, xspdPath **ret_path, char **ret_error_msg) {
	xspdPath *path;
	xspdTERAPATHSPath *pi;
	char *tps_server;
	char *mon_server;
	char *keyfile;
	char *keypass;
	char *cacerts;
	char *tps_src;
	char *tps_dst;
	char *tps_src_ports;
	char *tps_dst_ports;
	char *tps_bw_class;
	char *tps_direction;
	unsigned int tps_bw;
	unsigned int tps_start_time;
	int tps_duration;
	int tps_sleep_time;
	int tps_start_offset;
	int tps_timeout;
	int teardown_timeout;
	
	if (xspd_settings_get_2(settings, "terapaths", "server", &tps_server) != 0) {
                xspd_err(0, "No TERAPATHS server specified");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "monitor", &mon_server) != 0) {
		xspd_err(0, "No monitor server specified for TERAPATHS");
		mon_server = NULL;
	}
	
	if (xspd_settings_get_2(settings, "terapaths", "keyfile", &keyfile) != 0) {
                xspd_err(0, "No TERAPATHS keyfile specified");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "keypass", &keypass) != 0) {
                xspd_err(0, "No TERAPATHS keypass specified");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "cacerts", &cacerts) != 0) {
                xspd_err(0, "No TERAPATHS cacerts specified");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "bw_class", &tps_bw_class) != 0) {
		xspd_err(0, "No TERAPATHS bandwidth class specified");
		goto error_exit;
	}

	if (xspd_settings_get_int_2(settings, "terapaths", "duration", &tps_duration) != 0) {
                xspd_err(0, "No duration specified for TERAPATHS reservation");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "src", &tps_src) != 0) {
                xspd_err(0, "No TERAPATHS source prefix specified");
                goto error_exit;
        }

        if (xspd_settings_get_2(settings, "terapaths", "dst", &tps_dst) != 0) {
                xspd_err(0, "No TERAPATHS destination PREFIX specified");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "direction", &tps_direction) != 0) {
                xspd_err(0, "No TERAPATHS direction specified");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "src_ports", &tps_src_ports) != 0) {
                tps_src_ports = "";
        }

        if (xspd_settings_get_2(settings, "terapaths", "dst_ports", &tps_dst_ports) != 0) {
                tps_dst_ports = "";
        }
	
	if (xspd_settings_get_int_2(settings, "terapaths", "sleep_time", &tps_sleep_time) != 0) {
                tps_sleep_time = 5;
        }

	if (xspd_settings_get_int_2(settings, "terapaths", "start_offset", &tps_start_offset) != 0) {
                tps_start_offset = 5;
        }

	if (xspd_settings_get_int_2(settings, "terapaths", "start_time", &tps_start_time) != 0) {
		tps_start_time = 0;
        }

	if (xspd_settings_get_int_2(settings, "terapaths", "bandwidth", &tps_bw) != 0) {
		tps_bw = 0;
        }

	path = xspd_alloc_path();
	if (!path)
		goto error_exit;

	pi = xspd_alloc_terapaths_path();
	if (!pi)
		goto error_exit_path;
	
	pi->tsc.keyfile = keyfile;
	pi->tsc.keypass = keypass;
	pi->tsc.cacerts = cacerts;

	pi->tsc.soap_endpoint = tps_server;
	pi->tsc.soap_action = NULL;
	pi->tsc.namespaces = tps_namespaces;

	pi->msc.soap_endpoint = mon_server;
	pi->msc.soap_action = NULL;
	pi->msc.namespaces = mntr_namespaces;
	
	pi->src = tps_src;
	pi->dst = tps_dst;
	pi->src_ports = tps_src_ports;
	pi->dst_ports = tps_dst_ports;
	pi->start_time = (uint64_t)tps_start_time;
	pi->duration = (uint64_t)tps_duration;
	pi->bw = (uint64_t)tps_bw;
	pi->bw_used = 0;
	pi->bw_class = tps_bw_class;
	pi->direction = tps_direction;
	pi->sleep_time = tps_sleep_time;
	pi->start_offset = tps_start_offset;
	pi->type = PATH_SHARED;
	pi->status = TPS_DOWN;
	pi->reservation_id = NULL;
	
	path->path_private = pi;
	path->new_channel = xspd_terapaths_new_channel;
	path->resize_channel = xspd_terapaths_resize_channel;
	path->close_channel = xspd_terapaths_close_channel;
	path->free = xspd_terapaths_free_path;

	*ret_path = path;
	
	return 0;
	
 error_exit_path:
	*ret_error_msg = "path allocate configuration error";
	xspd_free_path(path);
 error_exit:
	return -1;
}

static char *xspd_terapaths_generate_path_id(const xspdSettings *settings, char **ret_error_msg) {
	char *tps_server;
	char *tps_src;
	char *tps_dst;
	char *path_id;	
	
        if (xspd_settings_get_2(settings, "terapaths", "server", &tps_server) != 0) {
                xspd_err(0, "No TERAPATHS server specified");
                goto error_exit;
        }

	if (xspd_settings_get_2(settings, "terapaths", "src", &tps_src) != 0) {
                xspd_err(0, "No TERAPATHS source prefix specified");
                goto error_exit;
        }

        if (xspd_settings_get_2(settings, "terapaths", "dst", &tps_dst) != 0) {
                xspd_err(0, "No TERAPATHS destination prefix specified");
                goto error_exit;
        }

        if (xspd_settings_get_2(settings, "terapaths", "path_id", &path_id) != 0) {
                if (ret_error_msg) {
                        if (asprintf(&path_id, "%s->%s@%s", tps_src, tps_dst, tps_server) <= 0) {
                                goto error_exit;
                        }
                }
        }

        return path_id;
	
 error_exit:
        return NULL;

}

static int xspd_terapaths_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg) {
	int retval;

        pthread_mutex_lock(&(path->lock));
        {
                retval = __xspd_terapaths_new_channel(path, size, channel, ret_error_msg);
        }
        pthread_mutex_unlock(&(path->lock));

        return retval;
}

static int __xspd_terapaths_new_channel(xspdPath *path, uint32_t size, xspdChannel **channel, char **ret_error_msg) {
	char *reservation_id;
	xspdTERAPATHSPath *pi = path->path_private;
	xspdChannel *new_channel;
	uint64_t new_bw = size;
	char *error_msg;
	char *status;

	path->tag++;
	pthread_cond_signal(&(path->timeout_cond));

	if (xspd_start_soap_ssl(&(pi->tsc)) != 0) {
		xspd_err(0, "couldn't start SOAP context");
		goto error_exit;
	}
	
	xspd_info(10,  "%s: reserving new channel of size: %lld", path->description, pi->bw);
	
	new_channel = xspd_alloc_channel();
	if (!channel) {
		xspd_err(0, "%s: couldn't allocate channel object", path->description);
                goto error_exit;
        }

	while (pi->status == TPS_STARTING) {
                pthread_cond_wait(&(pi->setup_cond), &(path->lock));
        }

	if (pi->status == TPS_DOWN) {
		uint64_t stime, etime;

		pi->status = TPS_STARTING;

		// TPs wants ms, not s
		if (pi->start_time <= 0)
			stime = (uint64_t)((uint64_t)time(NULL) + (uint64_t)pi->start_offset) * (uint64_t)1000;
		else
			stime = pi->start_time;

		etime = stime + (uint64_t)pi->duration;
		
		if (pi->bw <= 0)
			new_bw = size;
		else
			new_bw = pi->bw;

		xspd_info(0, "%s: the TERAPATHS path is down, reserving a new one", path->description);
		
		/*
		printf("soap-endpoint: %s\n", pi->tsc.soap_endpoint);
		printf("src: %s\n", pi->src);
		printf("dst: %s\n", pi->dst);
		printf("src-ports: %s\n", pi->src_ports);
		printf("dst-ports: %s\n", pi->dst_ports);
		printf("direction: %s\n", pi->direction);
		printf("bw-class: %s\n", pi->bw_class);
		printf("bw: %lld\n", new_bw);
		printf("st: %lld\n", stime);
		printf("duration: %lld\n", pi->duration);
		fflush(stdout);
		*/

		if (terapaths_reserve(&(pi->tsc), pi->src, pi->dst, pi->src_ports, pi->dst_ports, pi->direction,
				      pi->bw_class, new_bw, stime, pi->duration, &reservation_id) != 0) {
			pthread_cond_signal(&(pi->setup_cond));
			pi->status = TPS_DOWN;
			error_msg = "TPS RESERVE FAIL";
			xspd_err(0, "%s: could not reserve TERAPATHS path: %s", path->description, error_msg);
			fflush(stdout);
			*ret_error_msg = error_msg;
			goto error_exit_channel;
		}
		
		if (reservation_id)
			xspd_info(0, "%s: reservation accepted with ID: %s", path->description, reservation_id);
		

		if (terapaths_commit(&(pi->tsc), reservation_id) != 0) {
			pthread_cond_signal(&(pi->setup_cond));
                        pi->status = TPS_DOWN;
                        error_msg = "TPS COMMIT FAIL";
                        xspd_err(0, "%s: could not commit TERAPATHS reservation %s: %s",
				 path->description, reservation_id, error_msg);
                        *ret_error_msg = error_msg;
			goto error_exit_reservation;
		}

		xspd_info(0, "%s: allocated new path of size %lld (Start Time: %lld End Time: %lld). ID: %s",
			  path->description, new_bw, stime, etime, reservation_id);

		if (terapaths_get_related_ids(&(pi->tsc), reservation_id, &(pi->related_res_ids)) != 0) {
			error_msg = "TPS GET RELATED IDs FAIL";
			xspd_err(0, "%s: could not get related TERAPATHS reservation IDs %s: %s",
				 path->description, reservation_id, error_msg);
			*ret_error_msg = error_msg;
		}
		
		xspd_info(5, "%s: related reservation IDs: %s", path->description, pi->related_res_ids);

		strtok(pi->related_res_ids, "&");
		pi->vlan_tag = strtok(NULL, "&");
		pi->reservation_id = reservation_id;
		pi->bw = new_bw;
		pi->start_time = stime;
		pi->status = TPS_UP;

		xspd_info(0, "%s: starting path monitoring thread", path->description);
		xspd_tpool_exec(xspd_terapaths_monitor_path, path);
		
		pthread_cond_signal(&(path->timeout_cond));
	}
	else if (pi->type == PATH_SHARED) {
		new_bw = pi->bw;
		xspd_info(0, "%s: reusing existing path. Amount used: %lld/%lld", path->description, pi->bw_used, pi->bw);
	}
	else {
		xspd_err(0, "%s: Cannot resize paths", path->description);
		goto error_exit_channel;
	}
	
	pi->bw_used += new_bw;
	
	new_channel->bandwidth = (unsigned int)new_bw;

	LIST_INSERT_HEAD(&(path->channel_list), new_channel, path_entries);

        *channel = new_channel;

        xspd_info(10, "%s: allocated new channel of size: %u", path->description, new_channel->bandwidth);

        return 0;

 error_exit_reservation:
        if (terapaths_cancel(&(pi->tsc), reservation_id) != 0) {
		error_msg = "TPS CANCEL";
                xspd_err(0, "%s: couldn't cancel TERAPATHS path: %s", path->description, error_msg);
        }
	else
		xspd_info(0, "reservation %s canceled\n", reservation_id);
	pi->status = TPS_DOWN;
 error_exit_channel:
	xspd_stop_soap_ssl(&(pi->tsc));
        xspd_free_channel(new_channel);
 error_exit:
        return -1;
}
		
static int xspd_terapaths_close_channel(xspdPath *path, xspdChannel *channel) {
        int retval;

        pthread_mutex_lock(&(path->lock));
        {
                retval = __xspd_terapaths_close_channel(path, channel);
        }
        pthread_mutex_unlock(&(path->lock));

        return retval;
}

static int __xspd_terapaths_close_channel(xspdPath *path, xspdChannel *channel) {
	xspdTERAPATHSPath *pi = path->path_private;
	xspdChannel *curr_channel;

	xspd_info(0, "%s: shutting down channel", path->description);

        // verify that the channel passed is actually in the given path
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

        pi->bw_used -= channel->bandwidth;

	// if we have removed the last channel, close the path down
        if (path->channel_list.lh_first == NULL) {
                char *error_msg;
                xspd_info(10, "%s: no more channels, shutting down path", path->description);

		if (xspd_start_soap_ssl(&(pi->tsc)) != 0) {
			xspd_err(0, "couldn't start SOAP context");
			goto error_exit_path;
		}

		if (terapaths_cancel(&(pi->tsc), pi->reservation_id) != 0) {
			error_msg = "TPS CANCEL";
			xspd_err(0, "%s: couldn't cancel TERAPATHS path: %s", path->description, error_msg);
		}		
		xspd_info(10, "%s: successfully shutdown path", path->description);
		xspd_terapaths_reset_path_info(pi);
        }
	
        xspd_free_channel(channel);
	
        xspd_info(10, "%s: successfully shutdown channel", path->description);
	
	xspd_stop_soap_ssl(&(pi->tsc));

        return 0;

 error_exit_path:
	xspd_stop_soap_ssl(&(pi->tsc));
 error_exit:
        return -1;
}

static int xspd_terapaths_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg) {
	int retval;

        pthread_mutex_lock(&(path->lock));
        {
                retval = __xspd_terapaths_resize_channel(path, channel, new_size, ret_error_msg);
        }
        pthread_mutex_unlock(&(path->lock));

        return retval;
}

static int __xspd_terapaths_resize_channel(xspdPath *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg) {
	*ret_error_msg = strdup("channel resizing not supported");
        xspd_err(0, "channel resizing not supported");
        return -1;
}

static void xspd_terapaths_free_path(xspdPath *path) {
	xspd_free_terapaths_path((xspdTERAPATHSPath *) path->path_private);
	xspd_free_path(path);
}

static xspdTERAPATHSPath *xspd_alloc_terapaths_path() {
	xspdTERAPATHSPath *pi ;

        pi = malloc(sizeof(xspdTERAPATHSPath));
        if (!pi) {
                goto error_exit;
        }

        bzero(pi, sizeof(xspdTERAPATHSPath));

        if (pthread_cond_init(&(pi->setup_cond), NULL) != 0)
                goto error_exit_path;

        return pi;

 error_exit_path:
	free(pi);
 error_exit:
        return NULL;
}

static void xspd_free_terapaths_path(xspdTERAPATHSPath *pi) {
	if (pi->tsc.soap_endpoint)
		free(pi->tsc.soap_endpoint);
	if (pi->msc.soap_endpoint)
		free(pi->tsc.soap_endpoint);
        if (pi->src)
                free(pi->src);
        if (pi->dst)
                free(pi->dst);
	if (pi->src_ports)
		free(pi->src_ports);
	if (pi->dst_ports)
		free(pi->dst_ports);
	if (pi->bw_class)
		free(pi->bw_class);
	if (pi->direction)
		free(pi->direction);
        if (pi->reservation_id)
                free(pi->reservation_id);
	if (pi->related_res_ids)
		free(pi->related_res_ids);
        free(pi);
}

static void xspd_terapaths_reset_path_info(xspdTERAPATHSPath *pi) {
        if (pi->reservation_id)
                free(pi->reservation_id);
        pi->reservation_id = NULL;
	pi->start_time = 0;
        pi->bw_used = 0;
        //pi->bw = 0;
        pi->status = TPS_DOWN;
}

void *xspd_terapaths_monitor_path(void *args) {
	xspdPath *path = (xspdPath *)args;
	xspdTERAPATHSPath *pi = path->path_private;
	uint64_t rtime, ctime, etime, stime;
	
	int monitor=0;
	char *status;

	xspdSoapContext msc;
	xspdSoapContext tsc;

	xspd_copy_soap_context(&(pi->msc), &msc);
	xspd_copy_soap_context(&(pi->tsc), &tsc);

        if (xspd_start_soap_ssl(&tsc) != 0) {
		xspd_err(0, "couldn't start TPs SOAP context, thread exiting");
		return;
        }

	if (xspd_start_soap(&msc) != 0) {
		xspd_err(0, "couldn't start monitor SOAP context, thread exiting");
                return;
        }
	
        // now signal our monitoring frontend and start path monitoring thread
	do {
        	if (monitoring_notify(&msc, pi->reservation_id, pi->src, pi->dst, pi->src_ports, pi->dst_ports,
                             		pi->vlan_tag, pi->direction, pi->start_time/(uint64_t)1000,
                             		pi->duration, pi->bw, pi->bw_class, "pending") == 0) {
        		xspd_info(0, "%s: registered path (%s) at %s", path->description, pi->reservation_id, msc.soap_endpoint);
			monitor=1;
		}
        	else {
         		xspd_err(0, "%s: path notification failed!\n", path->description);
			sleep(5);
		}
	} while (!monitor);
	
	// wait until the reservation is supposed to be active
	ctime = (uint64_t)time(NULL);
	stime = (pi->start_time/(uint64_t)1000);
	
	//rtime = (pi->start_time/(uint64_t)1000) - pi->start_offset;

	//if ((long long int)(ctime-rtime) < 0) {
	//	xspd_err(0, "%s: reservation time is in the future!");
	//	return;
	//}
	
	//sleep(pi->start_offset - (ctime-rtime) + 5);
	//xspd_info(10, "%s: thread has awoken", path->description);
	
	// keep checking until active state is seen
	while (1) {
		// do some fancy TPs check here
		xspd_info(5, "%s: checking if path is active", path->description);
		
		if (xspd_terapaths_update_path_status(pi, &msc, &tsc, &status) == 0) {
			
			if (!strcmp(status, "active"))
				break;
			
			if (!strcmp(status, "deactivating") || !strcmp(status, "done") ||
			    !strcmp(status, "cancelling") || !strcmp(status, "cancelled") ||
			    !strcmp(status, "failed") || !strcmp(status, "activateFailed") ||
			    !strcmp(status, "cancelFailed") || !strcmp(status, "dirtyFailed") ||
			    !strcmp(status, "expired"))
				goto monitor_done;
		}

		// see if we've been checking forever
		ctime = (uint64_t)time(NULL);
		if ((long long int)(ctime-stime) > 300) {
			xspd_info(0, "%s: monitoring thread has timed out on active check");
			goto monitor_done;
		}

		sleep(5);
	}
	
	// this is when the reservation is supposed to end
	etime = stime + pi->duration;
	sleep(5);

	// keep checking until reservation is done
	while (1) {
		// check and update path status if not already expired
		xspd_terapaths_update_path_status(pi, &msc, &tsc, &status);

		// if status is anything other than a few cases, we're done
		if (status) {
			if (strcmp(status, "active") &&
			    strcmp(status, "deactivating") && strcmp(status, "cancelling"))
				goto monitor_done;
		}

		// say we're done after some time past the reservation end time
		ctime = (uint64_t)time(NULL);
		
		if ((long long int)((etime+20)-ctime) < 0) {
			xspd_err(0, "%s: reservation end time is already here!", path->description);
			monitoring_set_status(&msc, pi->reservation_id, "done");
			goto monitor_done;
		}
		
		sleep(10);
	}

 monitor_done:	
	// remove the path from monitoring
	xspd_info(10, "%s: deactivating monitoring and resetting path", path->description);
	//monitoring_remove(&msc, pi->reservation_id);

	// reset the path
	// channels on the path are still hanging around at this point
	xspd_terapaths_reset_path_info(pi);
	
	xspd_stop_soap_ssl(&tsc);
	xspd_stop_soap(&msc);

	// and we're done
	return;
}
	
int xspd_terapaths_update_path_status(xspdTERAPATHSPath *pi, xspdSoapContext *msc, xspdSoapContext *tsc, char **ret_status) {
	char *status;

	if (terapaths_get_reservation_status(tsc, pi->reservation_id, &status) == 0) {
		
		if (monitoring_set_status(msc, pi->reservation_id, status) != 0) {
			xspd_err(5, "(%s) couldn't set path status", pi->reservation_id);
		}
		else {
			xspd_info(8, "(%s) set path status to: %s", pi->reservation_id, status);
		}
		
		*ret_status = status;
	}
	
	else {
		xspd_err(5, "(%s) could not get TERAPATHS reservation status", pi->reservation_id);
		*ret_status = NULL;
		return -1;
	}
	return 0;
}
