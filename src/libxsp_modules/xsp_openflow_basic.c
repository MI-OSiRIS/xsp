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

#include "controller.h"
#include "xsp_openflow_basic.h"

#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_session.h"
#include "xsp_pathrule.h"
#include "xsp_pathrule_handler.h"
#include "hashtable.h"
#include "xsp_config.h"

// static global for the controller status
static int ctrl_status;

int xsp_openflow_init();
static int xsp_openflow_allocate_pathrule_handler(const xspNetPathRule *rule, const xspSettings *settings,
						  xspPathRule **ret_rule, char **ret_error_msg);
static char *xsp_openflow_generate_pathrule_id(const xspNetPathRule *rule, const xspSettings *settings, char **ret_error_msg);
static int xsp_openflow_apply_rule(xspPathRule *rule, int action, char **ret_error_msg);
static void xsp_openflow_free_rule(xspPathRule *rule);

static int __xsp_openflow_create_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_openflow_delete_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_openflow_modify_rule(xspPathRule *rule, char **ret_error_msg);

xspModule xsp_openflow_module = {
	.desc = "OPENFLOW Module",
	.dependencies = "",
	.init = xsp_openflow_init
};

xspPathRuleHandler xsp_openflow_pathrule_handler = {
	.name = "OPENFLOW",
	.allocate = xsp_openflow_allocate_pathrule_handler,
	.get_pathrule_id = xsp_openflow_generate_pathrule_id,
};

xspModule *module_info() {
	return &xsp_openflow_module;
}

int xsp_openflow_init() {
	ctrl_status = OF_CTRL_DOWN;

	// need a better interface for listener args
	// get OF listening port, etc. from XSP settings
	char *argv[2] = {"controller", "ptcp:1716"}; 

	// first, initialize the controller
	controller_init(2, argv);
	
	// start the controller
	controller_start();

	// check some return values before setting this
	ctrl_status = OF_CTRL_UP;

	// we should also get what switches we're controlling

	return xsp_add_pathrule_handler(&xsp_openflow_pathrule_handler);
}

static char *xsp_openflow_generate_pathrule_id(const xspNetPathRule *rule,
					       const xspSettings *settings,
					       char **ret_error_msg) {
	
	char *rule_id;

	// compose id from just the src/dst addrs for now
	if (asprintf(&rule_id, "%s->%s", 
		     rule->crit.src_eid.x_addrc,
		     rule->crit.dst_eid.x_addrc) <= 0) {
		goto error_exit;
	}
	
	return rule_id;
	
error_exit:
	*ret_error_msg = strdup("ERROR FORMING PATHRULE_ID");
	return NULL;
}

static int xsp_openflow_allocate_pathrule_handler(const xspNetPathRule *net_rule,
						  const xspSettings *settings,
						  xspPathRule **ret_rule,
						  char **ret_error_msg) {
	xspPathRule *rule;
	rule = xsp_alloc_pathrule();
	if (!rule)
		goto error_exit;
	
	if (net_rule->use_crit) {
		memcpy(&rule->crit, &net_rule->crit, sizeof(xspNetPathRuleCrit));
	}
	else {
		// check the settings for static openflow config
	}

	rule->private = NULL;
	rule->apply = xsp_openflow_apply_rule;
	rule->free = xsp_openflow_free_rule;
	
	*ret_rule = rule;

	return 0;

 error_exit_path:
	xsp_free_pathrule(rule);
	*ret_error_msg = strdup("pathrule allocate configuration error");
 error_exit:
	return -1;
}

static int xsp_openflow_apply_rule(xspPathRule *rule, int action, char **ret_error_msg) {
	int retval;
	char *error_msg = NULL;
	
	pthread_mutex_lock(&(rule->lock));
	{
		switch (action) {
		case XSP_NET_PATH_CREATE:
			retval = __xsp_openflow_create_rule(rule, &error_msg);
			break;
		case XSP_NET_PATH_DELETE:
			retval =  __xsp_openflow_delete_rule(rule, &error_msg);
			break;
		case XSP_NET_PATH_MODIFY:
			retval = __xsp_openflow_modify_rule(rule, &error_msg);
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

static int __xsp_openflow_create_rule(xspPathRule *rule, char **ret_error_msg) {

	// the question is what criteria do we apply
	// perhaps the controller API should just accept all the possible
	// fields in the OF tuple, and apply the flow entry with or without
	// wildcards

	// the other possibility is that we use the rule "op" field to determine
	// which OF fields we care about for a particular rule
	// the "operation" could be add an ACL, a route, filter, etc.

	if (ctrl_status == OF_CTRL_UP) {
		// right now all we can do it set the src/dst IP
		// ...and they're passed in as strings right now
		
		xsp_info(0, "adding OF rule: %s -> %s", rule->crit.src_eid.x_addrc, rule->crit.dst_eid.x_addrc);
		of_add_l3_rule(rule->crit.src_eid.x_addrc, rule->crit.dst_eid.x_addrc, 0, 0, 100);
	}
	else {
		xsp_err(0, "controller is not active\n");
		goto error_exit;
	}
	
	return 0;
	
 error_exit:
	return -1;
}

static int __xsp_openflow_modify_rule(xspPathRule *rule, char **ret_error_msg) {
	*ret_error_msg = strdup("OPENFLOW modify not supported");
	xsp_err(0, "OPENFLOW modify not supported");
	return -1;
}

static int __xsp_openflow_delete_rule(xspPathRule *rule, char **ret_error_msg) {
	if (ctrl_status == OF_CTRL_UP) {
		// right now all we can do it set the src/dst IP
		// ...and they're passed in as strings right now
		
		xsp_info(0, "removing OF rule: %s -> %s", rule->crit.src_eid.x_addrc, rule->crit.dst_eid.x_addrc);
		of_remove_l3_rule(rule->crit.src_eid.x_addrc, rule->crit.dst_eid.x_addrc, 0, 0);

	}
	else {
		xsp_err(0, "controller is not active\n");
                goto error_exit;
	}

	return 0;

 error_exit:
	return -1;
}

static void xsp_openflow_free_rule(xspPathRule *rule) {
	xsp_free_pathrule(rule);
}
