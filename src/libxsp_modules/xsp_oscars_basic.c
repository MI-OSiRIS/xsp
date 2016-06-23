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

#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_session.h"
#include "xsp_pathrule.h"
#include "xsp_pathrule_handler.h"
#include "hashtable.h"
#include "hashtable_util.h"
#include "xsp_main_settings.h"
#include "xsp_config.h"

#ifdef OSCARS5
#include "oscars.nsmap"
#endif

#ifdef OSCARS6
#include "oscars6.nsmap"
#endif

static struct hashtable *friendly_name;

typedef struct xsp_oscars_timeout_args {
	xspPathRule *rule;
	int tag;
	int timeout;
} xspOSCARSTimeoutArgs;

int xsp_oscars_init();
static void xsp_oscars_read_map();
static int xsp_oscars_allocate_pathrule_handler(const xspNetPathRule *rule, const xspSettings *settings,
						xspPathRule **ret_rule, char **ret_error_msg);
static char *xsp_oscars_generate_pathrule_id(const xspNetPathRule *rule, const xspSettings *settings, char **ret_error_msg);
static int xsp_oscars_apply_rule(xspPathRule *rule, int action, char **ret_error_msg);
static void xsp_oscars_free_rule(xspPathRule *rule);

static int __xsp_oscars_create_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_oscars_delete_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_oscars_modify_rule(xspPathRule *rule, char **ret_error_msg);

static xspOSCARSPath *xsp_alloc_oscars_path();
static void xsp_free_oscars_path(xspOSCARSPath *pi);
static void xsp_oscars_reset_rule_info();

static xspOSCARSTimeoutArgs *xsp_alloc_oscars_timeout_args();
static void *xsp_timeout_handler(void *arg);

xspModule xsp_oscars_module = {
	.desc = "OSCARS Module",
	.dependencies = "",
	.init = xsp_oscars_init
};

xspPathRuleHandler xsp_oscars_pathrule_handler = {
	.name = "OSCARS",
	.allocate = xsp_oscars_allocate_pathrule_handler,
	.get_pathrule_id = xsp_oscars_generate_pathrule_id,
};

xspModule *module_info() {
	return &xsp_oscars_module;
}

int xsp_oscars_init() {
	xsp_oscars_read_map();
	return xsp_add_pathrule_handler(&xsp_oscars_pathrule_handler);
}

static void xsp_oscars_read_map() {
	const xspSettings *settings;
	FILE *fp;
	char *map_file;
	char *line = NULL;
	int read;
	size_t len = 0;

	friendly_name = create_hashtable(16, xsp_hash_string, xsp_equalkeys_string);

	settings = xsp_main_settings();
	if (xsp_settings_get_3(settings, "paths", "oscars", "name_map", &map_file) != 0) {
		xsp_info(0, "No OSCARS friendly name map file specified, skipping");
		return;
        }

	fp = fopen(map_file, "r");
	if (!fp) {
		xsp_err(0, "Could not open OSCARS map file: %s", map_file);
		return;
	}
	
	while ((read = getline(&line, &len, fp)) != -1) {
		char *tok, *tok2;
		tok = strtok(line, " ");
		tok2 = strtok(NULL, " ");
		
		if (tok && tok2) {
			// strip newline
			tok2[strlen(tok2) - 1] = '\0';
			xsp_info(5, "Adding friendly name mapping: %s -> %s", tok, tok2);
			hashtable_insert(friendly_name, strdup(tok), strdup(tok2));
		}
		else {
			xsp_err(0, "Malformed OSCARS map file");
			return;
		}
	}
	
	fclose(fp);
}

static char *xsp_oscars_generate_pathrule_id(const xspNetPathRule *rule,
					     const xspSettings *settings,
					     char **ret_error_msg) {
	char *oscars_server;
	char *oscars_src_id;
	char *oscars_dst_id;
	char *oscars_src_vlan_id;
	char *oscars_dst_vlan_id;
	char *path_id;

	if (xsp_settings_get_2(settings, "oscars", "server", &oscars_server) != 0) {
		if (ret_error_msg) {
			xsp_err(0, "No OSCARS server specified");
			*ret_error_msg = strdup("No OSCARS server specified");
		}

		goto error_exit;
	}

	if (strlen(rule->crit.src_eid.x_addrc)) {
		oscars_src_id = (char*)rule->crit.src_eid.x_addrc;
	}
	else if (xsp_settings_get_2(settings, "oscars", "src_id", &oscars_src_id) != 0) {
		if (ret_error_msg) {
			xsp_err(0, "No OSCARS source identifier specified");
			*ret_error_msg = strdup("No OSCARS source identifier specified");
		}
		
		goto error_exit;
	}

	if (strlen(rule->crit.dst_eid.x_addrc)) {
		oscars_dst_id = (char*)rule->crit.dst_eid.x_addrc;
	}
	else if (xsp_settings_get_2(settings, "oscars", "dst_id", &oscars_dst_id) != 0) {
		if (ret_error_msg) {
			xsp_err(0, "No OSCARS destination identifier specified");
			*ret_error_msg = strdup("No OSCARS destination identifier specified");
		}

		goto error_exit;
	}

	if (rule->crit.src_vlan > 0) {
		asprintf(&oscars_src_vlan_id, "%d", rule->crit.src_vlan);
	}
	else {
		if (xsp_settings_get_2(settings, "oscars", "src_vlan_id", &oscars_src_vlan_id) != 0) {
			oscars_src_vlan_id = "N/A";
		}
	}

	if (rule->crit.dst_vlan > 0) {
		asprintf(&oscars_dst_vlan_id, "%d", rule->crit.dst_vlan);
	}
	else {
		if (xsp_settings_get_2(settings, "oscars", "dst_vlan_id", &oscars_dst_vlan_id) != 0) {
			oscars_dst_vlan_id = "N/A";
		}
	}		

	if (strcmp(oscars_src_id, oscars_dst_id) > 0) {
		char *tmp = oscars_src_id;
		oscars_src_id = oscars_dst_id;
		oscars_dst_id = tmp;
	}

	if (xsp_settings_get_2(settings, "oscars", "path_id", &path_id) != 0) {
		if (asprintf(&path_id, "%s(%s)->%s(%s)", oscars_src_id, oscars_src_vlan_id,
			     oscars_dst_id, oscars_dst_vlan_id) <= 0) {
			goto error_exit;
		}
	}

	return path_id;

error_exit:
	*ret_error_msg = strdup("ERROR");
	return NULL;
}

static int xsp_oscars_allocate_pathrule_handler(const xspNetPathRule *net_rule,
						const xspSettings *settings,
						xspPathRule **ret_rule,
						char **ret_error_msg) {
	xspPathRule *rule;
	xspOSCARSPath *pi;
	char *oscars_server;
	char *oscars_src_id;
	char *oscars_dst_id;
	int oscars_src_tagged;
	int oscars_dst_tagged;
	int oscars_duration;
	char *oscars_src_vlan_id;
	char *oscars_dst_vlan_id;
	int oscars_sleep_time;
	int oscars_clock_offset;
	int oscars_teardown_timeout;
	int oscars_reservation_timeout;
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

	if (net_rule->crit.duration > 0) {
		oscars_duration =  net_rule->crit.duration;
	}
	else if (xsp_settings_get_int_2(settings, "oscars", "duration", &oscars_duration) != 0) {
		xsp_err(0, "No duration specified for OSCARS reservation");
		goto error_exit;
	}

	if (strlen(net_rule->crit.src_eid.x_addrc)) {
		oscars_src_id = strdup(net_rule->crit.src_eid.x_addrc);
	}
	else if (xsp_settings_get_2(settings, "oscars", "src_id", &oscars_src_id) != 0) {
		xsp_err(0, "No OSCARS source identifier specified");
		goto error_exit;
	}
	
	if (strlen(net_rule->crit.dst_eid.x_addrc)) {
		oscars_dst_id = strdup(net_rule->crit.dst_eid.x_addrc);
	}
	else if (xsp_settings_get_2(settings, "oscars", "dst_id", &oscars_dst_id) != 0) {
		xsp_err(0, "No OSCARS destination identifier specified");
		goto error_exit;
	}
	
	if (xsp_settings_get_2(settings, "oscars", "type", &path_type_str) != 0) {
		path_type_str = "shared";
	}

	if (net_rule->crit.bandwidth > 0) {
		bandwidth = net_rule->crit.bandwidth;
	}
	else if (xsp_settings_get_int_2(settings, "oscars", "bandwidth", &bandwidth) != 0) {
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

	if (net_rule->crit.vlan > 0) {
                asprintf(&oscars_src_vlan_id, "%d", net_rule->crit.vlan);
                asprintf(&oscars_dst_vlan_id, "%d", net_rule->crit.vlan);
        }
	else {
		if (xsp_settings_get_2(settings, "oscars", "src_vlan_id", &oscars_src_vlan_id) != 0) {
			oscars_src_vlan_id = NULL;
		}
		
		if (xsp_settings_get_2(settings, "oscars", "dst_vlan_id", &oscars_dst_vlan_id) != 0) {
			oscars_dst_vlan_id = NULL;
		}
	}

	if (xsp_settings_get_int_2(settings, "oscars", "clock_offset", &oscars_clock_offset) != 0) {
		oscars_clock_offset = 0;
	}

	if (xsp_settings_get_int_2(settings, "oscars", "teardown_timeout", &oscars_teardown_timeout) != 0) {
		oscars_teardown_timeout = 0;
	}

	if (xsp_settings_get_int_2(settings, "oscars", "reservation_timeout", &oscars_reservation_timeout) != 0) {
                oscars_reservation_timeout = 90;
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

	rule = xsp_alloc_pathrule();
	if (!rule)
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
	pi->src_vlan_id = oscars_src_vlan_id;
	pi->dst_vlan_id = oscars_dst_vlan_id;
	pi->clock_offset = oscars_clock_offset;
	pi->sleep_time = oscars_sleep_time;
	pi->type = path_type;
	pi->bw = bandwidth;
	pi->teardown_timeout = oscars_teardown_timeout;
	pi->reservation_timeout = oscars_reservation_timeout;
	pi->intercircuit_pause_time = oscars_intercircuit_pause_time;
	pi->shutdown_time = 0;
	
	rule->private = pi;
	rule->apply = xsp_oscars_apply_rule;
	rule->free = xsp_oscars_free_rule;

	*ret_rule = rule;

	return 0;

 error_exit_path:
	xsp_free_pathrule(rule);
	*ret_error_msg = strdup("path allocate configuration error");
 error_exit:
	return -1;
}

static int xsp_oscars_apply_rule(xspPathRule *rule, int action, char **ret_error_msg) {
	int retval;
	char *error_msg = NULL;

	pthread_mutex_lock(&(rule->lock));
	{
		switch (action) {
		case XSP_NET_PATH_CREATE:
			retval = __xsp_oscars_create_rule(rule, &error_msg);
			break;
		case XSP_NET_PATH_DELETE:
			retval =  __xsp_oscars_delete_rule(rule, &error_msg);
			break;
		case XSP_NET_PATH_MODIFY:
			retval = __xsp_oscars_modify_rule(rule, &error_msg);
			break;
		default:
			xsp_err(0, "xsp_oscars_apply_rule(): unsupported action: %d", action);
			retval = -1;
			break;
		}
	}
	pthread_mutex_unlock(&(rule->lock));

	if (error_msg)
		*ret_error_msg = error_msg;

	return retval;
}

static int __xsp_oscars_create_rule(xspPathRule *rule, char **ret_error_msg) {
	char *reservation_id;
	xspOSCARSPath *pi = rule->private;
	uint32_t new_bandwidth = pi->bw;
	int reservation_timeout = pi->reservation_timeout;
	char *error_msg;
	void *response;
	char *status;
	int active = 0;
	int waiting = 0;

	rule->tag++;
	pthread_cond_signal(&(rule->timeout_cond));

	if (xsp_start_soap_ssl(&(pi->osc), SOAP_IO_DEFAULT, SOAP_SSL_NO_AUTHENTICATION) != 0) {
                xsp_err(0, "couldn't start SOAP context");
                goto error_exit;
        }
	
	xsp_info(10, "%s: applying new rule of size: %d", rule->description, new_bandwidth);
	
	if (pi->intercircuit_pause_time > 0) {
		time_t curr_time;
		
		time(&curr_time);
		
		if (curr_time < (pi->shutdown_time + pi->intercircuit_pause_time)) {
			xsp_info(5, "%s: sleeping for %lu seconds waiting for the circuit to become available",
				  rule->description, ((pi->shutdown_time + pi->intercircuit_pause_time) - curr_time));
			sleep((pi->shutdown_time + pi->intercircuit_pause_time) - curr_time);
		}
	}
	
	while (pi->status == OSCARS_STARTING) {
		pthread_cond_wait(&(pi->setup_cond), &(rule->lock));
	}

	if (pi->status == OSCARS_DOWN) {
		time_t stime, etime;
		OSCARS_resRequest create_req = {0};
		OSCARS_pathInfo path_info = {0};
		OSCARS_L2Info l2_info = {0};
		OSCARS_vlanTag l2_stag = {0};
		OSCARS_vlanTag l2_dtag = {0};
		
		pi->status = OSCARS_STARTING;		
		
		time(&stime);	
		stime += pi->clock_offset;
		etime = stime + pi->duration;
		
		xsp_info(0, "%s: the OSCARS path is down, allocating a new one", rule->description);
		
		if (!(l2_info.src_endpoint = hashtable_search(friendly_name, pi->src)))
			l2_info.src_endpoint = pi->src;
		if (!(l2_info.dst_endpoint = hashtable_search(friendly_name, pi->dst)))
			l2_info.dst_endpoint = pi->dst;
		
		l2_stag.id = pi->src_vlan_id;
		l2_dtag.id = pi->dst_vlan_id;

		l2_stag.tagged = (enum boolean_*)&(pi->src_tagged);
		l2_dtag.tagged = (enum boolean_*)&(pi->dst_tagged);
		
		l2_info.src_vlan = &l2_stag;
		l2_info.dst_vlan = &l2_dtag;

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
			xsp_err(0, "%s: couldn't reserve OSCARS path: %s", rule->description, error_msg);
			*ret_error_msg = error_msg;
			goto error_exit_channel;
		}
		
		reservation_id = ((struct ns1__createReply*)response)->globalReservationId;
		pi->reservation_id = strdup(reservation_id);

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
				xsp_err(0, "%s: couldn't create OSCARS path: %s", rule->description, error_msg);
				*ret_error_msg = error_msg;
				goto error_exit_reservation;
			}
			
			status = ((struct ns1__resDetails*)response)->status;
			xsp_info(10, "GRI %s status: %s", pi->reservation_id, status);

			if (strcmp(status,"ACTIVE") == 0){
				active=1;
				break;
			}
			
			if (strcmp(status,"FAILED") ==0){
				pthread_cond_signal(&(pi->setup_cond));
				pi->status = OSCARS_DOWN;
				error_msg = strdup("OSCARS STATUS: FAILED");
				//xsp_event("oscars.circuit.create.failure", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
				xsp_err(0, "%s: couldn't create OSCARS path: %s", rule->description, error_msg);
				*ret_error_msg = error_msg;
				goto error_exit_reservation;
			}
			
			waiting += pi->sleep_time;
                        if (waiting >= reservation_timeout) {
				pthread_cond_signal(&(pi->setup_cond));
				pi->status = OSCARS_DOWN;
				error_msg = strdup("OSCARS STATUS: TIMEDOUT");
				xsp_err(0, "%s: timed out waiting for OSCARS path: %s", rule->description, error_msg);
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
			 rule->description, new_bandwidth, (unsigned long) stime, (unsigned long) etime,
			 pi->reservation_id);
		
		// save the path information
		pi->bandwidth = new_bandwidth;
		
		pi->status = OSCARS_UP;
		
		pthread_cond_signal(&(rule->timeout_cond));
	} else if (pi->type == PATH_SHARED) {
		xsp_info(0, "%s: reusing existing rule. Amount used: %d/%d",
			 rule->description, pi->bandwidth_used, pi->bandwidth);
	} else {
	      /*
		uint32_t new_bandwidth;

		xsp_info(0, "%s: resizing path from %d to %d", rule->description, pi->bandwidth, new_bandwidth);

		// XXX: call oscars_modifyReservation() here

		xsp_info(10, "%s: path resized to %d Mbit/s. New id: %s", rule->description, new_bandwidth, reservation_id);

		free(pi->reservation_id);
		pi->reservation_id = reservation_id;
		pi->bandwidth = new_bandwidth;
	      */
		*ret_error_msg = strdup("OSCARS CAN'T SHARE");
		xsp_err(0, "%s: Can't resize OSCARS rules", rule->description);
		goto error_exit_channel;
	}
	
	pi->bandwidth_used += new_bandwidth;
	
	xsp_stop_soap_ssl(&(pi->osc));

	xsp_info(10, "%s: applied OSCARS rule of size: %d", rule->description, new_bandwidth);
	
	return 0;

 error_exit_reservation:
	if (oscars_cancelReservation(&(pi->osc), reservation_id, &response) != 0) {
		//xsp_event("oscars.circuit.close.failed", path,
		//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d SIZE=%lu ERROR_MSG=\"%s\"",
		//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, size, error_msg);
		xsp_err(0, "%s: couldn't apply OSCARS rule: %s", rule->description, error_msg);
	}
	pi->status = OSCARS_DOWN;
 error_exit_channel:
	xsp_stop_soap_ssl(&(pi->osc));
 error_exit:
	return -1;
}

static int __xsp_oscars_modify_rule(xspPathRule *rule, char **ret_error_msg) {
	*ret_error_msg = strdup("OSCARS resizing not supported");
	xsp_err(0, "OSCARS resizing not supported");
	return -1;
}

static int __xsp_oscars_delete_rule(xspPathRule *rule, char **ret_error_msg) {
	xspOSCARSPath *pi = rule->private;

	xsp_info(0, "%s: shutting down OSCARS rule with gri: %s",
		 rule->description, pi->reservation_id);

	void *response;
	if (xsp_start_soap_ssl(&(pi->osc), SOAP_IO_DEFAULT, SOAP_SSL_NO_AUTHENTICATION) != 0) {
		xsp_err(0, "couldn't start SOAP context");
		goto error_exit;
	}

	if (oscars_cancelReservation(&(pi->osc), pi->reservation_id, &response) != 0) {
		xsp_warn(0, "__xsp_oscars_delete_rule(%s): failed to delete rule",
			 pi->reservation_id);
		//xsp_event("oscars.circuit.close.failed", path,
		//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
		//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
	} else {
		xsp_info(10, "%s: successfully shutdown rule: gri: %s",
			 rule->description, pi->reservation_id);
		//xsp_event("oscars.circuit.close.failed", path,
		//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
		//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
	}

	xsp_oscars_reset_rule_info(pi);	
	xsp_stop_soap_ssl(&(pi->osc));
	
	return 0;

 error_exit:
	return -1;
}

static void *xsp_timeout_handler(void *arg) {
	xspOSCARSTimeoutArgs *args = arg;
	xspPathRule *rule = args->rule;
	int tag = args->tag;
	int timeout = args->timeout;
	xspOSCARSPath *pi = rule->private;
	void *response;

	pthread_mutex_lock(&(rule->lock));

	xsp_info(8, "Sleeping for %d seconds", timeout);
	// we have the tag check in here to make sure nothing changed between
	// when the closing thread launched us and when we were able to lock
	// the path structure.
	if (rule->tag == tag) {
		int n;
		struct timespec ts;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec + timeout;
		ts.tv_nsec = tv.tv_usec * 1000;

		n = pthread_cond_timedwait(&(rule->timeout_cond), &(rule->lock), &ts);

		xsp_debug(8, "Timeout handler kicked in");
		if (n == ETIMEDOUT) {
			xsp_debug(8, "A timeout occurred: closing path");
			
			if (xsp_start_soap_ssl(&(pi->osc), SOAP_IO_DEFAULT, SOAP_SSL_NO_AUTHENTICATION) != 0) {
                                xsp_err(0, "couldn't start SOAP context");
                                goto error_exit_path;
                        }
			
                        if (oscars_cancelReservation(&(pi->osc), pi->reservation_id, &response) != 0) {
				xsp_warn(0, "__xsp_oscars_delete_rule(%s): failed to delete rule",
					  rule->description);
				//xsp_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			} else {
				xsp_info(10, "%s: successfully shutdown path", rule->description);
				//xsp_event("oscars.circuit.close.failed", path,
				//	   "SRC_ID=\"%s\" DST_ID=\"%s\" IDC=\"%s\" VLAN=%d ERROR_MSG=\"%s\"",
				//	   pi->src, pi->dst, pi->osc.soap_endpoint, pi->vlan_id, error_msg);
			}
			time(&(pi->shutdown_time));
			xsp_oscars_reset_rule_info(pi);
			xsp_stop_soap_ssl(&(pi->osc));
		}
	}
	pthread_mutex_unlock(&(rule->lock));

 error_exit_path:
	xsp_stop_soap_ssl(&(pi->osc));

	return NULL;
}

static void xsp_oscars_reset_rule_info(xspOSCARSPath *pi) {
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
	if (pi->reservation_id)
		free(pi->reservation_id);
	if (pi->src)
		free(pi->src);
	if (pi->dst)
		free(pi->dst);
	free(pi);
}

static void xsp_oscars_free_rule(xspPathRule *rule) {
	xsp_free_oscars_path((xspOSCARSPath *) rule->private);
	xsp_free_pathrule(rule);
}
