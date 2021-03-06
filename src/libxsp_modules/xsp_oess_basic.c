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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include "curl_context.h"

#include "xsp_oess_basic.h"
#include "xsp_auth_cosign.h"

#include "xsp_auth.h"
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

#define OESS_AUTH_SERVICE "https://weblogin.grnoc.iu.edu/cosign-bin/cosign.cgi"
#define OESS_POST_FIELDS "ref=%s&service=cosign-os3e.net-I2&login=%s&password=%s&otp_user=%s&realm=%s&doLogin=Log+In"

// GLOBALS
static uint64_t entry_id;
static xspOESSConfig oess_config;
static char *OESS_SERVICE[5] = {"data.cgi", "measurement.cgi", "monitoring.cgi",
                                "provisioning.cgi", "remote.cgi"
                               };
// END GLOBALS

int xsp_oess_init();
static int xsp_oess_allocate_pathrule_handler(const xspNetPathRule *rule, const xspSettings *settings,
    xspPathRule **ret_rule, char **ret_error_msg);
static char *xsp_oess_generate_pathrule_id(const xspNetPathRule *rule, const xspSettings *settings,
    char **ret_error_msg);
static int xsp_oess_apply_rule(xspPathRule *rule, int action, char **ret_error_msg);
static void xsp_oess_free_rule(xspPathRule *rule);
static int __xsp_oess_create_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_oess_delete_rule(xspPathRule *rule, char **ret_error_msg);
static int __xsp_oess_modify_rule(xspPathRule *rule, char **ret_error_msg);

xspModule xsp_oess_module = {
  .desc = "OESS Module",
  .dependencies = "auth_cosign",
  .init = xsp_oess_init
};

xspPathRuleHandler xsp_oess_pathrule_handler = {
  .name = "OESS",
  .allocate = xsp_oess_allocate_pathrule_handler,
  .get_pathrule_id = xsp_oess_generate_pathrule_id,
};

xspModule *module_info() {
  return &xsp_oess_module;
}

int xsp_oess_init() {
  const xspSettings *settings;
  xspAuthenticationHandler *handler;

  // get and save oess server URL from config here
  settings = xsp_main_settings();
  if (xsp_settings_get_3(settings, "paths", "oess", "server", &oess_config.service_ap) != 0) {
    xsp_info(0, "No OESS URL specified!");
    return -1;
  }

  if (xsp_settings_get_3(settings, "paths", "oess", "login", &oess_config.login) != 0) {
    xsp_info(0, "No OESS login name");
    return -1;
  }

  if (xsp_settings_get_3(settings, "paths", "oess", "password", &oess_config.password) != 0) {
    xsp_info(0, "No OESS password");
    return -1;
  }

  if (xsp_settings_get_3(settings, "paths", "oess", "realm", &oess_config.realm) != 0) {
    xsp_info(0, "No OESS realm");
    return -1;
  }

  if (xsp_settings_get_3(settings, "paths", "oess", "project", &oess_config.project) != 0) {
    xsp_info(0, "No OESS login project");
    return -1;
  }

  // make sure we can have the cosign auth handler present
  handler = xsp_get_authentication_handler("COSIGN");
  if (!handler) {
    xsp_err(0, "Could not find COSIGN auth handler");
    return -1;
  }

  // use cosign auth as interface to the OESS API
  oess_config.auth_handler = handler;
  entry_id = 0;

  return xsp_add_pathrule_handler(&xsp_oess_pathrule_handler);
}

static char *xsp_oess_generate_pathrule_id(const xspNetPathRule *rule,
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
    // check the settings for static oess config
    if (xsp_settings_get_2(settings, "oess", "src_eid", &src_eid) != 0) {
      xsp_err(0, "No OESS src specified");
      goto error_exit;
    }

    if (xsp_settings_get_2(settings, "oess", "dst_eid", &dst_eid) != 0) {
      xsp_err(0, "No OESS dst specified");
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

static int xsp_oess_allocate_pathrule_handler(const xspNetPathRule *net_rule,
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
    // check the settings for static oess config
    if (xsp_settings_get_2(settings, "oess", "src_eid", &src_eid) != 0) {
      xsp_err(0, "No OESS src specified");
      goto error_exit_pathrule;
    }

    if (xsp_settings_get_2(settings, "oess", "dst_eid", &dst_eid) != 0) {
      xsp_err(0, "No OESS dst specified");
      goto error_exit_pathrule;
    }

    memcpy(rule->crit.src_eid.x_addrc, src_eid, XSP_HOPID_LEN);
    memcpy(rule->crit.dst_eid.x_addrc, dst_eid, XSP_HOPID_LEN);
  }

  memcpy(&(rule->eid), &(net_rule->eid), sizeof(struct xsp_addr));

  rule->private = NULL;
  rule->apply = xsp_oess_apply_rule;
  rule->free = xsp_oess_free_rule;

  *ret_rule = rule;

  return 0;

error_exit_pathrule:
  xsp_free_pathrule(rule);
  *ret_error_msg = strdup("pathrule allocate configuration error");
error_exit:
  return -1;
}

static int xsp_oess_apply_rule(xspPathRule *rule, int action, char **ret_error_msg) {
  int retval;
  char *error_msg = NULL;

  pthread_mutex_lock(&(rule->lock));
  {
    switch (action) {
    case XSP_NET_PATH_CREATE:
      retval = __xsp_oess_create_rule(rule, &error_msg);
      break;
    case XSP_NET_PATH_DELETE:
      retval =  __xsp_oess_delete_rule(rule, &error_msg);
      break;
    case XSP_NET_PATH_MODIFY:
      retval = __xsp_oess_modify_rule(rule, &error_msg);
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

static int __xsp_oess_create_rule(xspPathRule *rule, char **ret_error_msg) {
  char *oess_url;
  char *response;
  xspAuthenticationHandler *ah = (xspAuthenticationHandler*)oess_config.auth_handler;
  xspCosignUserInfo *auth_info;
  xspCreds *creds;
  curl_context *cc;
  curl_response *crr;
  char *post_fields;

  cc = (curl_context*)ah->get_auth_context();
  if (!cc) {
    xsp_err(0, "Could not get authentication context");
    return -1;
  }

  // OESS_SERVICE[],login,password,login,realm
  asprintf(&post_fields, OESS_POST_FIELDS, OESS_SERVICE[OESS_PROVISIONING], oess_config.login,
           oess_config.password, oess_config.login, oess_config.realm);

  // in the future, path setup auth info might come in over the session
  // so we create this context on-demand
  auth_info = xsp_alloc_cosign_user_info();
  auth_info->username = oess_config.login;
  auth_info->password = oess_config.password;
  auth_info->auth_service = OESS_AUTH_SERVICE;
  auth_info->post_fields = post_fields;
  auth_info->institution = oess_config.realm;

  creds = malloc(sizeof(xspCreds));
  creds->private = auth_info;

  // construct the URL
  asprintf(&oess_url, "%s/%s", oess_config.service_ap, OESS_SERVICE[OESS_PROVISIONING]);

  if (ah->authenticate_interactive(creds, oess_url, &response)) {
    xsp_err(0, "OESS auth failed: %s", response);
    return -1;
  }

  // authentication succeeded, perform the action at the service
  curl_post(cc,
            oess_url,
            NULL,
            NULL,
            NULL,
            NULL,
            &crr);

  if (crr->data)
    xsp_info(0, "\nOESS response: \n%s\n", crr->data);

  return 0;
}

static int __xsp_oess_delete_rule(xspPathRule *rule, char **ret_error_msg) {

  return 0;
}

static int __xsp_oess_modify_rule(xspPathRule *rule, char **ret_error_msg) {
  *ret_error_msg = strdup("OESS modify not supported");
  xsp_err(0, "OESS modify not supported");
  return -1;
}

static void xsp_oess_free_rule(xspPathRule *rule) {
  xsp_free_pathrule(rule);
}
