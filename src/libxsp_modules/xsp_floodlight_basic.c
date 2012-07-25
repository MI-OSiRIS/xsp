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

#include "compat.h"

#include "xsp_floodlight_basic.h"

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

int xsp_floodlight_init();
static int xsp_floodlight_allocate_pathrule_handler(const xspNetPathRule *rule, const xspSettings *settings,
						  xspPathRule **ret_rule, char **ret_error_msg);
static char *xsp_floodlight_generate_pathrule_id(const xspNetPathRule *rule, const xspSettings *settings, char **ret_error_msg);
static int xsp_floodlight_apply_rule(xspPathRule *rule, int action, char **ret_error_msg);
static void xsp_floodlight_free_rule(xspPathRule *rule);

static int __xsp_floodlight_create_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_floodlight_delete_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_floodlight_modify_rule(xspPathRule *rule, char **ret_error_msg);

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
	
	char **src_list;
	char **dst_list;
	int src_count;
	int dst_count;
	char *src_eid;
	char *dst_eid;

	struct xsp_floodlight_rules_t *prules = NULL;

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
	rule->private = NULL;
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
	struct xsp_floodlight_rules_t *prules = rule->private;
        int i;

	return 0;

 error_exit:
	return -1;
}

static void xsp_floodlight_free_rule(xspPathRule *rule) {
	xsp_free_pathrule(rule);
}