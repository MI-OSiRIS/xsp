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
#ifndef XSP_AUTHENTICATION_H
#define XSP_AUTHENTICATION_H

#include "xsp_conn.h"
#include "xsp_session.h"
#include "xsp-proto.h"
#include "libxsp_proto.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif


typedef struct xsp_credentials_t {
  char *type;
  void *private;
  const char *(*get_user) (struct xsp_credentials_t *credentials);
  const char *(*get_email) (struct xsp_credentials_t *credentials);
  const char *(*get_institution) (struct xsp_credentials_t *credentials);
  void (*free) (struct xsp_credentials_t *credentials);
#ifdef HAVE_OPENSSL
  SSL_CTX *ctx;
  BIO *sbio;
  SSL *ssl;
#endif
} xspCreds;

/*
 *  int xsp_authentication_init():
 *      This function initializes the authentication subsystem.
 */
int xsp_authentication_init();

/*
 * This structure is registered with the authentication subsystem to allow a new authentication to be added
 *  name: Plaintext name for the authentication(e.g. ANON, GLOBUS, REALID).
 *  authenticate: Function pointer to the authentication routine. It
 *                authenticates the connection using whatever means and returns
 *                a 0 if successful. The credentials are stored in the
 *                ret_creds parameter.
 *
 *  request_authentication: Function pointer to a function that handles
 *                          authenticating with a remote server. The function
 *                          returns a 0 if authentication was successful and
 *                          non-zero otherwise.
 */
typedef struct xsp_authentication_handler_t {
  char name[XSP_AUTH_NAME_LEN + 1];
  int (*authenticate) (xspConn *conn, xspCreds **ret_creds);
  int (*request_authentication) (comSess *sess, xspConn *conn);
  int (*authenticate_interactive) (xspCreds *creds, const char *input, char **output);
  void *(*get_auth_context) (void);
} xspAuthenticationHandler;

/*
 *  int xsp_add_authentication(xspProtocolHandler *handler):
 *      This function adds the given authentication handler to the list of authentication handlers. It returns 0 if successful.
 */
int xsp_add_authentication_handler(xspAuthenticationHandler *handler);
int xsp_authenticate_connection(xspConn *conn, xspMsg *msg, xspCreds **ret_creds);
int xsp_request_authentication(comSess *sess, xspConn *new_conn, const char *auth_name);
xspAuthenticationHandler *xsp_get_authentication_handler(const char *name);

#endif
