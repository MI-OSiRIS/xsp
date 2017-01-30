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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <jansson.h>

#include "curl_context.h"
#include "queue.h"
#include "hashtable.h"
#include "libunis_c_log.h"

#include "xsp_session.h"
#include "xsp_tpool.h"
#include "xsp_listener.h"
#include "xsp_settings.h"
#include "xsp_main_settings.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_protocols.h"
#include "xsp_config.h"
#include "xsp_auth.h"
#include "xsp_modules.h"
#include "xsp_pathrule.h"
#include "xsp_pathrule_handler.h"
#include "libconfig.h"

int xsp_flange_init();
static char *xsp_flange_generate_pathrule_id(const xspNetPathRule *rule, const xspSettings *settings,
					     char **ret_error_msg);
static int xsp_flange_allocate_pathrule_handler(const xspNetPathRule *rule, const xspSettings *settings,
						xspPathRule **ret_rule, char **ret_error_msg);

xspModule xsp_flange_module = {
  .desc = "Flange Module",
  .dependencies = "",
  .init = xsp_flange_init,
};

xspModule *module_info() {
  return &xsp_flange_module;
}

xspPathRuleHandler xsp_flange_pathrule_handler = {
  .name = "FLANGE",
  .allocate = xsp_flange_allocate_pathrule_handler,
  .get_pathrule_id = xsp_flange_generate_pathrule_id,
};

int xsp_flange_init() {
  const xspSettings *settings;
  char *controller;
  
  // get and save floodlight host/ip from config here
  settings = xsp_main_settings();
  if (xsp_settings_get_3(settings, "paths", "flange", "controller", &controller) != 0) {
    xsp_info(0, "No Flange controller specified!");
  }

  // register this path rule handler
  return xsp_add_pathrule_handler(&xsp_flange_pathrule_handler);
}

static char *xsp_flange_generate_pathrule_id(const xspNetPathRule *rule,
					     const xspSettings *settings,
					     char **ret_error_msg) {

  return "Flange Rule";
}

static int xsp_flange_allocate_pathrule_handler(const xspNetPathRule *net_rule,
						const xspSettings *settings,
						xspPathRule **ret_rule,
						char **ret_error_msg) {
  
  xspPathRule *rule;
  rule = xsp_alloc_pathrule();
  if (!rule)
    goto error_exit;

  if (net_rule->data_size) {
    xsp_info(9, "got rule data of size: %d\n%s",
	     net_rule->data_size,
	     net_rule->data);
  }
  
  // define these methods
  rule->apply = NULL;
  rule->free = NULL;

  *ret_rule = rule;
  
  return 0;

 error_exit:
  return -1;
}
