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

#include "xsp_linuxnet.h"

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

int xsp_linuxnet_init();
static int xsp_linuxnet_allocate_pathrule_handler(const xspNetPathRule *rule, const xspSettings *settings,
    xspPathRule **ret_rule, char **ret_error_msg);
static char *xsp_linuxnet_generate_pathrule_id(const xspNetPathRule *rule, const xspSettings *settings, char **ret_error_msg);
static int xsp_linuxnet_apply_rule(xspPathRule *rule, int action, char **ret_error_msg);
static void xsp_linuxnet_free_rule(xspPathRule *rule);

static int __xsp_linuxnet_check_iface(char *iface);
static int __xsp_linuxnet_exec_cmd(char *cmd);

static int __xsp_linuxnet_create_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_linuxnet_delete_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_linuxnet_modify_rule(xspPathRule *rule, char **ret_error_msg);

static struct xsp_linuxnet_cfg_t ln_cfg = {
  .iface_list = NULL,
  .iface_count = 0
};

xspModule xsp_linuxnet_module = {
  .desc = "LINUXNET Module",
  .dependencies = "",
  .init = xsp_linuxnet_init
};

xspPathRuleHandler xsp_linuxnet_pathrule_handler = {
  .name = "LINUXNET",
  .allocate = xsp_linuxnet_allocate_pathrule_handler,
  .get_pathrule_id = xsp_linuxnet_generate_pathrule_id,
};

xspModule *module_info() {
  return &xsp_linuxnet_module;
}

int xsp_linuxnet_init() {
  const xspSettings *settings;
  int iface_count;
  char **iface_list;

  settings = xsp_main_settings();
  // check the settings for linuxnet config
  if (xsp_settings_get_list_3(settings, "paths", "linuxnet", "iface_list",
                              &iface_list, &iface_count) != 0) {
    xsp_warn(0, "No LINUXNET ifaces specified");
  }

  if (iface_count) {
    ln_cfg.iface_list = iface_list;
    ln_cfg.iface_count = iface_count;
  }
  else {
    ln_cfg.iface_list = (char**)malloc(sizeof(char *));
    ln_cfg.iface_list[0] = "lo";
    ln_cfg.iface_count = 1;
  }

  return xsp_add_pathrule_handler(&xsp_linuxnet_pathrule_handler);
}

static char *xsp_linuxnet_generate_pathrule_id(const xspNetPathRule *rule,
    const xspSettings *settings,
    char **ret_error_msg) {
  char *rule_id = NULL;
  char *src_eid;
  char *dst_eid;
  uint16_t vlan = 0;

  if (rule->use_crit) {
    switch (rule->op) {
    case XSP_LINUXNET_SET_IP: {
      // src_eid contains interface name we want to configure
      src_eid = (char*)rule->crit.src_eid.x_addrc;
      if (!__xsp_linuxnet_check_iface(src_eid)) {
        xsp_err(0, "requested interface %s is not configurable", src_eid);
        goto error_exit;
      }

      // dst_eid contains the IP we want to give the interface
      // assume HRN (dotted octets) form
      dst_eid = (char*)rule->crit.dst_eid.x_addrc;
    }
    break;
    case XSP_LINUXNET_SET_VLAN: {
      // src_eid contains interface name we want to configure
      src_eid = (char*)rule->crit.src_eid.x_addrc;
      if (!__xsp_linuxnet_check_iface(src_eid)) {
        xsp_err(0, "requested interface %s is not configurable", src_eid);
        goto error_exit;
      }

      dst_eid = "";
      vlan = rule->crit.vlan;
    }
    break;
    case XSP_LINUXNET_SET_ROUTE: {
      // do route setup
      src_eid = "";
      dst_eid = "";
    }
    break;
    default:
      xsp_err(0, "unsupported LINUXNET operation: %d", rule->op);
      goto error_exit;
      break;
    }
  }
  else {
    // check the settings for static linuxnet config
    xsp_info(0, "no static config, not doing anything!");
    goto error_exit;
  }

  if (asprintf(&rule_id, "%s:%s:%s:%d", op_map[rule->op], src_eid, dst_eid, vlan) <= 0) {
    goto error_exit;
  }

  return rule_id;

error_exit:
  *ret_error_msg = strdup("ERROR FORMING PATHRULE_ID");
  return NULL;
}

static int xsp_linuxnet_allocate_pathrule_handler(const xspNetPathRule *net_rule,
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

  memcpy(&(rule->eid), &(net_rule->eid), sizeof(struct xsp_addr));
  rule->op = net_rule->op;
  rule->private = NULL;
  rule->apply = xsp_linuxnet_apply_rule;
  rule->free = xsp_linuxnet_free_rule;

  *ret_rule = rule;

  return 0;

error_exit:
  return -1;
}

static int xsp_linuxnet_apply_rule(xspPathRule *rule, int action, char **ret_error_msg) {
  int retval;
  char *error_msg = NULL;

  pthread_mutex_lock(&(rule->lock));
  {
    switch (action) {
    case XSP_NET_PATH_CREATE:
      retval = __xsp_linuxnet_create_rule(rule, &error_msg);
      break;
    case XSP_NET_PATH_DELETE:
      retval =  __xsp_linuxnet_delete_rule(rule, &error_msg);
      break;
    case XSP_NET_PATH_MODIFY:
      retval = __xsp_linuxnet_modify_rule(rule, &error_msg);
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

static int __xsp_linuxnet_create_rule(xspPathRule *rule, char **ret_error_msg) {

  FILE *output;
  char *cmd = NULL;

  switch (rule->op) {
  case XSP_LINUXNET_SET_IP: {
    if (rule->crit.vlan > 0) {
      asprintf(&cmd, "sudo ifconfig %s.%d %s netmask %s up",
               rule->crit.src_eid.x_addrc, rule->crit.vlan,
               rule->crit.dst_eid.x_addr,
               rule->crit.dst_mask.x_addrc);
    }
    else {
      asprintf(&cmd, "sudo ifconfig %s %s netmask %s up",
               rule->crit.src_eid.x_addrc,
               rule->crit.dst_eid.x_addr,
               rule->crit.dst_mask.x_addrc);
    }
    __xsp_linuxnet_exec_cmd(cmd);
  }
  break;
  case XSP_LINUXNET_SET_VLAN: {
    asprintf(&cmd, "sudo vconfig add %s %d",
             rule->crit.src_eid.x_addrc, rule->crit.vlan);
    __xsp_linuxnet_exec_cmd(cmd);
  }
  break;
  case XSP_LINUXNET_SET_ROUTE: {
    struct in_addr in_addr, in_mask, in_net;
    char *net_addr;
    inet_aton(rule->crit.src_eid.x_addrc, &in_addr);
    inet_aton(rule->crit.src_mask.x_addrc, &in_mask);
    in_net.s_addr = (in_addr.s_addr & in_mask.s_addr);
    net_addr = inet_ntoa(in_net);

    asprintf(&cmd, "sudo ip route add %s/%s via %s",
             net_addr,
             rule->crit.src_mask.x_addrc,
             rule->crit.dst_eid.x_addrc);
    __xsp_linuxnet_exec_cmd(cmd);
  }
  break;
  default:
    break;
  }

  return 0;

error_exit:
  return -1;
}

static int __xsp_linuxnet_modify_rule(xspPathRule *rule, char **ret_error_msg) {
  *ret_error_msg = strdup("LINUXNET modify not supported");
  xsp_err(0, "LINUXNET modify not supported");
  return -1;
}

static int __xsp_linuxnet_delete_rule(xspPathRule *rule, char **ret_error_msg) {

  char *cmd = NULL;

  switch (rule->op) {
  case XSP_LINUXNET_SET_IP: {
    if (rule->crit.vlan > 0) {
      asprintf(&cmd, "sudo ip addr flush dev %s.%d",
               rule->crit.src_eid.x_addrc, rule->crit.vlan);
    }
    else {
      asprintf(&cmd, "sudo ip addr flush dev %s",
               rule->crit.src_eid.x_addrc);
    }
    __xsp_linuxnet_exec_cmd(cmd);
  }
  break;
  case XSP_LINUXNET_SET_VLAN: {
    asprintf(&cmd, "sudo vconfig rem %s.%d",
             rule->crit.src_eid.x_addrc, rule->crit.vlan);
    __xsp_linuxnet_exec_cmd(cmd);
  }
  break;
  case XSP_LINUXNET_SET_ROUTE: {
    struct in_addr in_addr, in_mask, in_net;
    char *net_addr;
    inet_aton(rule->crit.src_eid.x_addrc, &in_addr);
    inet_aton(rule->crit.src_mask.x_addrc, &in_mask);
    in_net.s_addr = (in_addr.s_addr & in_mask.s_addr);
    net_addr = inet_ntoa(in_net);

    asprintf(&cmd, "sudo ip route del %s/%s via %s",
             net_addr,
             rule->crit.src_mask.x_addrc,
             rule->crit.dst_eid.x_addrc);
    __xsp_linuxnet_exec_cmd(cmd);
  }
  break;
  default:
    break;
  }

  return 0;

error_exit:
  return -1;
}

static void xsp_linuxnet_free_rule(xspPathRule *rule) {
  xsp_free_pathrule(rule);
}

static int __xsp_linuxnet_check_iface(char *iface) {
  int i;

  // check to see if this is an interface we can configure
  for (i = 0; i < ln_cfg.iface_count; i++) {
    if (!strncmp(iface, ln_cfg.iface_list[i], strlen(iface)))
      return 1;
  }

  return 0;
}

static int __xsp_linuxnet_exec_cmd(char *cmd) {
  FILE *output;

  xsp_info(11, "executing \"%s\"", cmd);
  output = popen(cmd, "r");
  pclose(output);

  return 0;
}
