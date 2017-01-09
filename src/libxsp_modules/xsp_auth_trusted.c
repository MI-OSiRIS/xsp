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

#include "xsp_auth.h"
#include "xsp_modules.h"

#include "compat.h"

typedef struct xsp_auth_trusted_user_info_t {
  char *username;
  char *email;
  char *institution;
} xspTrustedUserInfo;

xspTrustedUserInfo *xsp_alloc_trusted_user_info();
void xsp_free_trusted_user_info(xspTrustedUserInfo *ui);

static int xsp_auth_trusted_init();
static int xsp_auth_trusted_authenticate(xspConn *conn, xspCreds **ret_creds);
static int xsp_auth_trusted_request_authentication (comSess *sess, xspConn *conn);
const char *xsp_auth_trusted_get_user(xspCreds *credentials);
const char *xsp_auth_trusted_get_institution(xspCreds *credentials);
const char *xsp_auth_trusted_get_email(xspCreds *credentials);
static void xsp_auth_trusted_free_credentials(xspCreds *credentials);

static xspAuthenticationHandler xsp_auth_trusted_handler = {
  .authenticate = xsp_auth_trusted_authenticate,
  .request_authentication = xsp_auth_trusted_request_authentication,
  .name = "TRUST",
};

static xspModule xsp_auth_trusted_module = {
  .desc = "Trusted Authentication Module",
  .dependencies = "",
  .init = xsp_auth_trusted_init
};

xspModule *module_info() {
  return &xsp_auth_trusted_module;
}

int xsp_auth_trusted_init() {
  return xsp_add_authentication_handler(&xsp_auth_trusted_handler);
}

const char *xsp_auth_trusted_get_user(xspCreds *credentials) {
  xspTrustedUserInfo *ui = (xspTrustedUserInfo *) credentials->private;
  return ui->username;
}

const char *xsp_auth_trusted_get_institution(xspCreds *credentials) {
  xspTrustedUserInfo *ui = (xspTrustedUserInfo *) credentials->private;
  return ui->institution;
}

const char *xsp_auth_trusted_get_email(xspCreds *credentials) {
  xspTrustedUserInfo *ui = (xspTrustedUserInfo *) credentials->private;
  return ui->email;
}

void xsp_auth_trusted_free_credentials(xspCreds *credentials) {
  xspTrustedUserInfo *ui = (xspTrustedUserInfo *) credentials->private;
  xsp_free_trusted_user_info(ui);
  free(credentials);
}

int xsp_auth_trusted_request_authentication (comSess *sess, xspConn *conn) {
  xspAuthToken xsp_token;
  char buf[1024];

  snprintf(buf, sizeof(buf), "%s|%s|%s",sess->credentials->get_email(sess->credentials),
           sess->credentials->get_email(sess->credentials),
           sess->credentials->get_institution(sess->credentials));

  xsp_token.token_length = strlen(buf);
  xsp_token.token = buf;

  xspMsg auth_msg = {
    .version = sess->version,
    .type = XSP_MSG_AUTH_TOKEN,
    .flags = 0,
    .msg_body = &xsp_token
  };
  xsp_conn_send_msg(conn, &auth_msg, XSP_OPT_AUTH_TOK);

  return 0;
}

int xsp_auth_trusted_authenticate(xspConn *conn, xspCreds **ret_creds) {
  xspCreds *creds;
  xspTrustedUserInfo *ui;
  xspMsg *msg;
  xspAuthToken *xsp_token;
  char **columns;
  int column_count;
  char buf[1024];

  msg = xsp_conn_get_msg(conn, 0);
  if (!msg)
    goto error_exit;

  if (msg->type != XSP_MSG_AUTH_TOKEN)
    goto error_exit2;

  xsp_token = msg->msg_body;

  bzero(buf, sizeof(buf));

  if (xsp_token->token_length >= 1024)
    goto error_exit2;

  // with a length < 1024 and a count of 1024, copying to buf will mean
  // that buf is null terminated
  bcopy(xsp_token->token, buf, xsp_token->token_length);

  columns = split(buf, "|", &column_count);
  if (!columns)
    goto error_exit2;

  if (column_count != 3)
    goto error_exit3;

  creds = malloc(sizeof(xspCreds));
  if (!creds)
    goto error_exit3;

  ui = xsp_alloc_trusted_user_info();
  if (!ui)
    goto error_exit4;

  ui->username = columns[0];
  ui->email = columns[1];
  ui->institution = columns[2];

  free(columns);

  creds->type = "TRUST";
  creds->private = ui;
  creds->get_user = xsp_auth_trusted_get_user;
  creds->get_email = xsp_auth_trusted_get_email;
  creds->get_institution = xsp_auth_trusted_get_institution;
  creds->free = xsp_auth_trusted_free_credentials;

  *ret_creds = creds;

  return 0;

error_exit4:
  free(creds);
error_exit3:
  strlist_free(columns, column_count);
error_exit2:
  xsp_free_msg(msg);
error_exit:
  return -1;
}

xspTrustedUserInfo *xsp_alloc_trusted_user_info() {
  xspTrustedUserInfo *ui;

  ui = malloc(sizeof(xspTrustedUserInfo));
  if (!ui)
    goto error_exit;

  bzero(ui, sizeof(xspTrustedUserInfo));

  return ui;

error_exit:
  return NULL;
}

void xsp_free_trusted_user_info(xspTrustedUserInfo *ui) {
  if (ui->username)
    free(ui->username);
  if (ui->email)
    free(ui->email);
  if (ui->institution)
    free(ui->institution);
  free(ui);
}
