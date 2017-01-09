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
#include <stdlib.h>
#include <string.h>

#include "config.h"

#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#endif

#include "xsp_auth_cosign.h"
#include "xsp_modules.h"
#include "xsp_session.h"
#include "xsp_conn.h"
#include "xsp_auth.h"
#include "xsp_logger.h"
#include "xsp_config.h"

#include "curl_context.h"
#include "compat.h"

/* GLOBALS */
static curl_context cc;
/* END GLOBALS */

xspModule *module_info();
static int xsp_cosign_auth_init();
static int xsp_cosign_auth_authenticate(xspConn *conn, xspCreds **ret_creds);
static int xsp_cosign_auth_request_authentication(comSess *sess, xspConn *conn);
static int xsp_cosign_auth_handle_url(xspCreds *creds, const char *url, char **response);
static void *xsp_cosign_get_curl_context();
static const char *xsp_cosign_auth_get_user(xspCreds *creds);
static const char *xsp_cosign_auth_get_email(xspCreds *creds);
static const char *xsp_cosign_auth_get_institution(xspCreds *creds);
static void xsp_cosign_auth_free_credentials(xspCreds *credentials);
static int __xsp_sanity_check_username(const char *username, int length);

static xspAuthenticationHandler xsp_cosign_auth_handler = {
  .name = "COSIGN",
  .authenticate = xsp_cosign_auth_authenticate,
  .request_authentication = xsp_cosign_auth_request_authentication,
  .authenticate_interactive = xsp_cosign_auth_handle_url,
  .get_auth_context = xsp_cosign_get_curl_context,
};

static xspModule xsp_cosign_auth_module = {
  .desc = "COSIGN Authentication Module",
  .dependencies = "",
  .init = xsp_cosign_auth_init
};

xspModule *module_info() {
  return &xsp_cosign_auth_module;
}

int xsp_cosign_auth_init() {
  cc.use_ssl = 1;
  cc.use_cookies = 1;
  cc.curl_persist = 0;
  cc.follow_redirect = 1;

  if (init_curl(&cc, 0) != 0) {
    xsp_info(0, "Could not start CURL context");
    return -1;
  }

  return xsp_add_authentication_handler(&xsp_cosign_auth_handler);
}

void *xsp_cosign_get_curl_context() {
  return (void*)&cc;
}

static int __xsp_sanity_check_username(const char *username, int length) {
  int i;

  for(i = 0; i < length; i++) {
    if (username[i] >= 'a' && username[i] <= 'z')
      continue;

    if (username[i] >= 'A' && username[i] <= 'Z')
      continue;

    if (username[i] >= '0' && username[i] <= '9')
      continue;

    if (username[i] == '_' || username[i] == '-')
      continue;

    return -1;
  }

  return 0;
}

static int xsp_cosign_auth_handle_url(xspCreds *creds, const char *url, char **response) {
  xspCosignUserInfo *ui = creds->private;
  curl_response *cr;
  char *curl_url = (char *)url;
  char *accept_type = "Accept: text/html";

  *response = NULL;
  cc.follow_redirect = 0;
  curl_get(&cc,
           curl_url,
           accept_type,
           &cr);

  // auth succeeded and we can return with success
  if (cr->status == 200) {
    return 0;
  }
  // we've been redirected, complete the auth with libcurl automatically following links
  else if (cr->status == 302) {
    curl_response *crr_redir;
    curl_response *crr_post;
    curl_response *crr_get;

    cc.follow_redirect = 1;

    // get to login page
    curl_get(&cc,
             cr->redirect_url,
             accept_type,
             &crr_redir);
    free_curl_response(crr_redir);

    // post credentials
    curl_post(&cc,
              ui->auth_service,
              accept_type,
              NULL,
              ui->post_fields,
              NULL,
              &crr_post);
    free_curl_response(crr_post);

    // get the original URL and return success if status is good
    curl_get(&cc,
             curl_url,
             accept_type,
             &crr_get);
    free_curl_response(crr_get);

    if (crr_get->status == 200) {
      free_curl_response(cr);
      return 0;
    }
  }
  else {
    // service is otherwise not available
    // return whatever the page content is
    *response = malloc(strlen(cr->data) * sizeof(char));
    memcpy(*response, cr->data, strlen(cr->data)+1);
  }

  free_curl_response(cr);
  return -1;
}

static int xsp_cosign_auth_request_authentication(comSess *sess, xspConn *conn) {

  // TODO

  return 0;
}

static int xsp_cosign_auth_authenticate(xspConn *conn, xspCreds **ret_creds) {
  xspCreds *creds;
  xspMsg *msg1;
  xspAuthToken *recv_token;
  char username[255];
  xspCosignUserInfo *ui = NULL;

  creds = malloc(sizeof(xspCreds));
  if (!creds)
    goto error_exit;

  msg1 = xsp_conn_get_msg(conn, 0);
  if (!msg1)
    goto error_exit;

  if (msg1->type != XSP_MSG_AUTH_TOKEN)
    goto error_exit2;

  recv_token = msg1->msg_body;

  if (recv_token->token_length >= 255)
    goto error_exit2;

  // validate that the username doesn't contain junk characters and such
  if (__xsp_sanity_check_username(recv_token->token, recv_token->token_length))
    goto error_exit2;

  // get a null-terminated copy of the username
  bcopy(recv_token->token, username, recv_token->token_length);
  username[recv_token->token_length] = '\0';

  xsp_info(0, "user %s attempting to connect", username);

  // complete cosign auth over XSP conn ...
  creds->type = "COSIGN";
  creds->get_user = xsp_cosign_auth_get_user;
  creds->get_email = xsp_cosign_auth_get_email;
  creds->get_institution = xsp_cosign_auth_get_institution;
  creds->free = xsp_cosign_auth_free_credentials;
  creds->private = ui;

  *ret_creds = creds;

  xsp_free_msg(msg1);

  return 0;

error_exit2:
  xsp_free_msg(msg1);
error_exit:
  return -1;
}

static void xsp_cosign_auth_free_credentials(xspCreds *credentials) {
  xspCosignUserInfo *ui = (xspCosignUserInfo *) credentials->private;

  xsp_free_cosign_user_info(ui);
  free(credentials);
}

xspCosignUserInfo *xsp_alloc_cosign_user_info() {
  xspCosignUserInfo *ui;

  ui = malloc(sizeof(xspCosignUserInfo));
  if (!ui)
    goto error_exit;

  bzero(ui, sizeof(xspCosignUserInfo));

  return ui;

error_exit:
  return NULL;
}

void xsp_free_cosign_user_info(xspCosignUserInfo *ui) {
  if (ui->username != NULL)
    free(ui->username);
  if (ui->password != NULL)
    free(ui->password);
  if (ui->email != NULL)
    free(ui->email);
  if (ui->institution != NULL)
    free(ui->institution);
  free(ui);
}

static const char *xsp_cosign_auth_get_user(xspCreds *creds) {
  xspCosignUserInfo *ui = creds->private;
  return ui->username;
}

static const char *xsp_cosign_auth_get_email(xspCreds *creds) {
  xspCosignUserInfo *ui = creds->private;
  return ui->email;
}

static const char *xsp_cosign_auth_get_institution(xspCreds *creds) {
  xspCosignUserInfo *ui = creds->private;
  return ui->institution;
}
