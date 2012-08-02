#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#ifdef HAVE_SENDFILE_H
#include <sys/sendfile.h>
#endif
#include <unistd.h>

#include <jansson.h>

#include "compat.h"

#include "xsp_floodlight_basic.h"
#include "xsp_curl_context.h"

#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_session.h"
#include "xsp_main_settings.h"
#include "xsp_pathrule.h"
#include "xsp_pathrule_handler.h"
#include "hashtable.h"
#include "xsp_config.h"

// GLOBALS
static uint64_t entry_id;
static xspFLConfig fl_config;

static xspCURLContext curl_context;
// END GLOBALS

int xsp_floodlight_init();
static int xsp_floodlight_allocate_pathrule_handler(const xspNetPathRule *rule, const xspSettings *settings,
						    xspPathRule **ret_rule, char **ret_error_msg);
static char *xsp_floodlight_generate_pathrule_id(const xspNetPathRule *rule, const xspSettings *settings,
						 char **ret_error_msg);
static int xsp_floodlight_apply_rule(xspPathRule *rule, int action, char **ret_error_msg);
static void xsp_floodlight_free_rule(xspPathRule *rule);
static int __xsp_floodlight_create_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_floodlight_delete_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_floodlight_modify_rule(xspPathRule *rule, char **ret_error_msg);
static json_t *__xsp_floodlight_make_entry(xspPathRule *rule);
static json_t *__xsp_floodlight_push_entry(json_t *entry, int rest_opt);
static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp);

xspModule xsp_floodlight_module = {
	.desc = "FLOODLIGHT Module",
	.dependencies = "",
	.init = xsp_floodlight_init
};

xspPathRuleHandler xsp_floodlight_pathrule_handler = {
	.name = "FLOODLIGHT",
	.allocate = xsp_floodlight_allocate_pathrule_handler,
	.get_pathrule_id = xsp_floodlight_generate_pathrule_id,
};

xspModule *module_info() {
	return &xsp_floodlight_module;
}

int xsp_floodlight_init() {
	const xspSettings *settings;

	// get and save floodlight host/ip from config here	
	settings = xsp_main_settings();
        if (xsp_settings_get_3(settings, "paths", "floodlight", "controller", &fl_config.controller_hp) != 0) {
		xsp_info(0, "No Floodlight controller specified!");
                return -1;
        }

	curl_context.url = fl_config.controller_hp;
	curl_context.use_ssl = 0;
	curl_context.curl_persist = 0;

	if (xsp_init_curl(&curl_context, NULL) != 0) {
		xsp_info(0, "Could not start CURL context");
		return -1;
	}

	entry_id = 0;

	return xsp_add_pathrule_handler(&xsp_floodlight_pathrule_handler);
}

static char *xsp_floodlight_generate_pathrule_id(const xspNetPathRule *rule,
						 const xspSettings *settings,
						 char **ret_error_msg) {
	
	char *rule_id;
	char *src_eid;
	char *dst_eid;
	uint32_t sport;
	uint32_t dport;
	uint64_t dpid;

        if (rule->use_crit) {
		// compose id from just the src/dst addrs for now
		src_eid = (char*)rule->crit.src_eid.x_addrc;
		dst_eid = (char*)rule->crit.dst_eid.x_addrc;
		sport = rule->crit.src_port;
		dport = rule->crit.dst_port;
		dpid = rule->eid.x_addrd;
        }
        else {
                // check the settings for static floodlight config
                if (xsp_settings_get_2(settings, "floodlight", "src_eid", &src_eid) != 0) {
                        xsp_err(0, "No FLOODLIGHT src specified");
                        goto error_exit;
                }

                if (xsp_settings_get_2(settings, "floodlight", "dst_eid", &dst_eid) != 0) {
                        xsp_err(0, "No FLOODLIGHT dst specified");
                        goto error_exit;
                }
		
                sport = 0;
                dport = 0;
                dpid = 0;
        }

	if (asprintf(&rule_id, "%"PRIX64"=>%u:%s->%u:%s", dpid, sport, src_eid, dport, dst_eid) <= 0) {
		goto error_exit;
	}

	return rule_id;
	
error_exit:
	*ret_error_msg = strdup("ERROR FORMING PATHRULE_ID");
	return NULL;
}

static int xsp_floodlight_allocate_pathrule_handler(const xspNetPathRule *net_rule,
						    const xspSettings *settings,
						    xspPathRule **ret_rule,
						    char **ret_error_msg) {	
	char *src_eid;
	char *dst_eid;

	xspPathRule *rule;
	rule = xsp_alloc_pathrule();
	if (!rule)
		goto error_exit;
	
	if (net_rule->use_crit) {
		memcpy(&rule->crit, &net_rule->crit, sizeof(xspNetPathRuleCrit));
	}
	else {
		// check the settings for static floodlight config
		if (xsp_settings_get_2(settings, "floodlight", "src_eid", &src_eid) != 0) {
			xsp_err(0, "No FLOODLIGHT src specified");
			goto error_exit_pathrule;
		}
		
		if (xsp_settings_get_2(settings, "floodlight", "dst_eid", &dst_eid) != 0) {
                        xsp_err(0, "No FLOODLIGHT dst specified");
                        goto error_exit_pathrule;
                }
		
		memcpy(rule->crit.src_eid.x_addrc, src_eid, XSP_HOPID_LEN);
		memcpy(rule->crit.dst_eid.x_addrc, dst_eid, XSP_HOPID_LEN);
	}

	memcpy(&(rule->eid), &(net_rule->eid), sizeof(struct xsp_addr));

	// keep track of which entries get pushed via FL for this rule
	xspFLEntries *fle  = (xspFLEntries *)malloc(sizeof(xspFLEntries));
	fle->entries = NULL;
	fle->n_entries = 0;
	
	rule->private = fle;
	rule->apply = xsp_floodlight_apply_rule;
	rule->free = xsp_floodlight_free_rule;
	
	*ret_rule = rule;

	return 0;

 error_exit_pathrule:
	xsp_free_pathrule(rule);
	*ret_error_msg = strdup("pathrule allocate configuration error");
 error_exit:
	return -1;
}

static int xsp_floodlight_apply_rule(xspPathRule *rule, int action, char **ret_error_msg) {
	int retval;
	char *error_msg = NULL;
	
	pthread_mutex_lock(&(rule->lock));
	{
		switch (action) {
		case XSP_NET_PATH_CREATE:
			retval = __xsp_floodlight_create_rule(rule, &error_msg);
			break;
		case XSP_NET_PATH_DELETE:
			retval =  __xsp_floodlight_delete_rule(rule, &error_msg);
			break;
		case XSP_NET_PATH_MODIFY:
			retval = __xsp_floodlight_modify_rule(rule, &error_msg);
			break;
		default:
			xsp_err(0, "Unsupported action: %d", action);
			retval = -1;
			break;
		}
	}
	pthread_mutex_unlock(&(rule->lock));
	
	if (error_msg)
		*ret_error_msg = error_msg;
	
	return retval;
}

static int __xsp_floodlight_create_rule(xspPathRule *rule, char **ret_error_msg) {
	
	xspFLEntries *fle = (xspFLEntries*)rule->private;
	json_t *fl_entry;
	json_t *j_resp;

	fl_entry = __xsp_floodlight_make_entry(rule);
	
	printf("PUSHING FLOODLIGHT ENTRY:\n%s\n", json_dumps(fl_entry, JSON_INDENT(2)));

	j_resp = __xsp_floodlight_push_entry(fl_entry, CURLOPT_POST);
	if (j_resp)
		printf("RESPONSE: \n%s\n", json_dumps(j_resp, JSON_INDENT(2)));

	// save entry names for delete/modify
	if (!(fle->n_entries)) {
		fle->entries = (xspFLEntries**)malloc(sizeof(xspFLEntries*));
		fle->entries[0] = fl_entry;
		fle->n_entries = 1;
	}
	else {
		int new_size = fle->n_entries+1;
		fle->entries = realloc(fle->entries, new_size*sizeof(xspFLEntries*));
		fle->entries[fle->n_entries] = fl_entry;
		fle->n_entries++;
	}
	
	// incrememnt global id
	entry_id++;

	return 0;
	
 error_exit:
	return -1;
}

static int __xsp_floodlight_modify_rule(xspPathRule *rule, char **ret_error_msg) {
	*ret_error_msg = strdup("FLOODLIGHT modify not supported");
	xsp_err(0, "FLOODLIGHT modify not supported");
	return -1;
}

static int __xsp_floodlight_delete_rule(xspPathRule *rule, char **ret_error_msg) {
	xspFLEntries *fle = (xspFLEntries*)rule->private;
	int i;

	for (i=0; i<fle->n_entries; i++) {
		
	}
	return 0;

 error_exit:
	return -1;
}

static void xsp_floodlight_free_rule(xspPathRule *rule) {
	xsp_free_pathrule(rule);
}

// build a json object for FL out of the rule
static json_t *__xsp_floodlight_make_entry(xspPathRule *rule) {
	json_t *obj = json_object();
	char *entry_name;
	char *entry_action;;

	if (!obj) {
		xsp_err(10, "could not create new json object");
		return NULL;
	}

	asprintf(&entry_name, "xsp-fl-%llu", entry_id);
	// more logic needed to determine the correct action
	// assume OUTPUT for now
	asprintf(&entry_action, "output=%d", rule->crit.dst_port);

	if (rule->eid.type == XSP_EID_DPIDC)
		json_object_set_new(obj, "switch", json_string(rule->eid.x_addrc));
	
	json_object_set_new(obj, "name", json_string(entry_name));

	//json_object_set_new(obj, "src-mac", json_string(rule->crit.l2_src));
	//json_object_set_new(obj, "dst-mac", json_string(rule->crit.l2_dst));
	json_object_set_new(obj, "ingress-port", json_integer(rule->crit.src_port));
	json_object_set_new(obj, "vlan-id", json_integer(rule->crit.src_vlan));
	json_object_set_new(obj, "active", json_string("true"));
	json_object_set_new(obj, "actions", json_string(entry_action));

	return obj;
}

static json_t *__xsp_floodlight_push_entry(json_t *entry, int rest_opt) {
	json_t *json_ret;;
	json_error_t json_err;
	char *json_str;
	char *response;

	json_str = json_dumps(entry, JSON_COMPACT);

	xsp_curl_json_string(&curl_context,
			     "/wm/staticflowentrypusher/json",
			     rest_opt,
			     json_str,
			     &response);
	
	json_ret = json_loads(response, 0, &json_err);
	if (!json_ret) {
		xsp_info(5, "Could not decode response: %d: %s", json_err.line, json_err.text);
		return NULL;
	}
	
	return json_ret;
}
