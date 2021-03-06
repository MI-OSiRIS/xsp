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
#define _GNU_SOURCE
#include <stdio.h>

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

static struct curl_context_t cc;

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
  char *controller, *user, *pass;
  
  // get and save floodlight host/ip from config here
  settings = xsp_main_settings();
  if (xsp_settings_get_3(settings, "paths", "flange", "controller", &controller) != 0) {
    xsp_info(0, "No Flange controller specified!");
  }
  if (xsp_settings_get_3(settings, "paths", "flange", "username", &user) != 0) {
    xsp_info(0, "No Flange controller username specified!");
  }
  if (xsp_settings_get_3(settings, "paths", "flange", "password", &pass) != 0) {
    xsp_info(0, "No Flange controller password specified!");
  }

  cc.url = controller;
  cc.username = user;
  cc.password = pass;
  cc.use_ssl = 0;
  cc.curl_persist = 0;

  if (init_curl(&cc, 0) != 0) {
    xsp_info(0, "Could not start CURL context");
    return -1;
  }
  
  // now let's get an auth token from flanged
  char *url;
  json_t *json_ret;
  json_error_t json_err;
  curl_response *response;

  asprintf(&url, "%s/%s", cc.url, "a");
  curl_get(&cc, url, NULL, &response);

  if (!response) {
    xsp_err(0, "No response from flanged at %s", url);
    return -1;
  }
  
  if (response->status == 200) {
    json_ret = json_loads(response->data, 0, &json_err);
    if (!json_ret) {
      xsp_info(5, "Could not decode response: %d: %s", json_err.line, json_err.text);
      return -1;
    }
  }
  else {
    xsp_err(0, "Bad response from flanged: %ld", response->status);
    return -1;
  }

  const char *token;
  int rc = json_unpack(json_ret, "{s:s}", "Bearer", &token);
  if (rc) {
    xsp_info(5, "Could not parse Authentication response: \n%s", response->data);
    return -1;
  }
  
  xsp_info(9, "flanged Bearer token: %s", token);
  cc.oauth_token = (char*)token;
  
  free(url);

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

  char *url;
  char *pstr;
  json_t *json_ret;
  json_error_t json_err;
  curl_response *response;
  
  xspPathRule *rule;
  rule = xsp_alloc_pathrule();
  if (!rule)
    goto error_exit;

  if (net_rule->data_size) {
    xsp_info(9, "got rule data of size: %d\n%s",
	     net_rule->data_size,
	     net_rule->data);
  }

  asprintf(&url, "%s/%s", cc.url, "c");
  asprintf(&pstr, "{\"program\": \"%s\"}", net_rule->data);
  curl_post(&cc, url, NULL, NULL, NULL, pstr, &response);

  if (!response) {
    xsp_err(0, "No response from flanged at %s", url);
    return -1;
  }
  
  json_ret = json_loads(response->data, 0, &json_err);
  if (!json_ret) {
    xsp_info(5, "Could not decode response: %d: %s", json_err.line, json_err.text);
    return -1;
  }

  xsp_info(5, "Compiler response: \n%s", response->data);
  
  // define these methods
  rule->apply = NULL;
  rule->free = NULL;

  *ret_rule = rule;

  free(url);
  free(pstr);
  
  return 0;

 error_exit:
  return -1;
}
