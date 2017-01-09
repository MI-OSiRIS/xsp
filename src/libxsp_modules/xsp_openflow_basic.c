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

#include "controller.h"
#include "xsp_openflow_basic.h"

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
  const xspSettings *settings;
  char *pvconn;
  ctrl_status = OF_CTRL_DOWN;

  // need a better interface for listener args
  // get OF listening port, etc. from XSP settings
  settings = xsp_main_settings();
  if (xsp_settings_get_2(settings, "openflow", "controller_pvconn", &pvconn) != 0) {
    xsp_warn(0, "No OPENFLOW controller_pvconn specified, using ptcp:1716");
    pvconn = "ptcp:1716";
  }

  char *argv[2] = {"controller", pvconn};

  // first, initialize the controller
  if (controller_init(2, argv) != 0)
    return -1;

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
    // check the settings for static openflow config
    if (xsp_settings_get_2(settings, "openflow", "src_eid", &src_eid) != 0) {
      xsp_err(0, "No OPENFLOW src specified");
      goto error_exit;
    }

    if (xsp_settings_get_2(settings, "openflow", "dst_eid", &dst_eid) != 0) {
      xsp_err(0, "No OPENFLOW dst specified");
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

static int xsp_openflow_allocate_pathrule_handler(const xspNetPathRule *net_rule,
    const xspSettings *settings,
    xspPathRule **ret_rule,
    char **ret_error_msg) {

  char **src_list;
  char **dst_list;
  int src_count;
  int dst_count;
  char *src_eid;
  char *dst_eid;

  struct xsp_openflow_rules_t *prules = NULL;

  xspPathRule *rule;
  rule = xsp_alloc_pathrule();
  if (!rule)
    goto error_exit;

  if (net_rule->use_crit) {
    memcpy(&rule->crit, &net_rule->crit, sizeof(xspNetPathRuleCrit));
  }
  else {
    // check the settings for static openflow config
    if (xsp_settings_get_2(settings, "openflow", "src_eid", &src_eid) != 0) {
      xsp_err(0, "No OPENFLOW src specified");
      goto error_exit_pathrule;
    }

    if (xsp_settings_get_2(settings, "openflow", "dst_eid", &dst_eid) != 0) {
      xsp_err(0, "No OPENFLOW dst specified");
      goto error_exit_pathrule;
    }

    memcpy(rule->crit.src_eid.x_addrc, src_eid, XSP_HOPID_LEN);
    memcpy(rule->crit.dst_eid.x_addrc, dst_eid, XSP_HOPID_LEN);
  }

  // let's be sneaky and add more entries if they're defined in the config
  xsp_settings_get_list_2(settings, "openflow", "src_list", &src_list, &src_count);
  xsp_settings_get_list_2(settings, "openflow", "dst_list", &dst_list, &dst_count);

  if (src_count && dst_count) {
    prules = malloc(sizeof(struct xsp_openflow_rules_t));
    prules->src_list = src_list;
    prules->dst_list = dst_list;
    prules->src_count = src_count;
    prules->dst_count = dst_count;
  }

  memcpy(&(rule->eid), &(net_rule->eid), sizeof(struct xsp_addr));
  rule->private = prules;
  rule->apply = xsp_openflow_apply_rule;
  rule->free = xsp_openflow_free_rule;

  *ret_rule = rule;

  return 0;

error_exit_pathrule:
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

  struct xsp_openflow_rules_t *prules = rule->private;
  int i;

  if (ctrl_status == OF_CTRL_UP) {
    xsp_info(0, "adding OF rule: %s->%s@%"PRIX64"", rule->crit.src_eid.x_addrc, rule->crit.dst_eid.x_addrc,
             rule->eid.x_addrd);
    of_add_l3_rule(rule->eid.x_addrd, rule->crit.src_eid.x_addrc,
                   rule->crit.dst_eid.x_addrc, rule->crit.src_port, rule->crit.dst_port, 100);

    if (prules && (prules->src_count == prules->dst_count)) {
      for (i = 0; i < prules->src_count; i++) {
        xsp_info(0, "adding OF rule: %s -> %s", prules->src_list[i], prules->dst_list[i]);
        of_add_l3_rule(0, prules->src_list[i], prules->dst_list[i], 0, 0, 100);
      }
    }
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
  struct xsp_openflow_rules_t *prules = rule->private;
  int i;

  if (ctrl_status == OF_CTRL_UP) {
    // right now all we can do it set the src/dst IP
    // ...and they're passed in as strings right now

    xsp_info(0, "removing OF rule: %s->%s@%"PRIX64"", rule->crit.src_eid.x_addrc, rule->crit.dst_eid.x_addrc,
             rule->eid.x_addrd);
    of_remove_l3_rule(rule->eid.x_addrd, rule->crit.src_eid.x_addrc, rule->crit.dst_eid.x_addrc, 0, 0);

    if (prules && (prules->src_count == prules->dst_count)) {
      for (i = 0; i < prules->src_count; i++) {
        xsp_info(0, "removing OF rule: %s -> %s", prules->src_list[i], prules->dst_list[i]);
        of_remove_l3_rule(0, prules->src_list[i], prules->dst_list[i], 0, 0);
      }
    }
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
