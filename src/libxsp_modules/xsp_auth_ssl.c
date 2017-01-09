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
#include <openssl/sha.h>
#include <openssl/err.h>

#include "config.h"
#include "xsp_modules.h"
#include "xsp_session.h"
#include "xsp_conn.h"
#include "xsp_auth.h"
#include "xsp_auth_ssl.h"
#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_conn_tcp.h"

#include "compat.h"

static char *pass;
static char *server_pem;
static char *server_root_pem;
static char *client_name;
static int s_server_session_id_context = 1;
static BIO *bio_err = NULL;

static int password_cb(char *buf, int num, int rwflag, void *userdata);
static SSL_CTX *initialize_ctx(char *keyfile, char *password);

static int xsp_ssl_auth_init();
static int xsp_ssl_auth_authenticate(xspConn *conn, xspCreds **ret_creds);
static int xsp_ssl_auth_request_authentication(comSess *sess, xspConn *conn);
static void xsp_ssl_auth_free_credentials(xspCreds *credentials);
static const char *xsp_ssl_auth_get_user(xspCreds *creds);
static const char *xsp_ssl_auth_get_email(xspCreds *creds);
static const char *xsp_ssl_auth_get_institution(xspCreds *creds);

//static void __xsp_rand_fill(unsigned char *buf, int length);

static xspAuthenticationHandler xsp_ssl_auth_handler = {
  .name = "SSL",
  .authenticate = xsp_ssl_auth_authenticate,
  .request_authentication = xsp_ssl_auth_request_authentication,
};

static xspModule xsp_ssl_auth_module = {
  .desc = "SSL Certificate Authentication Module",
  .dependencies = "",
  .init = xsp_ssl_auth_init
};

xspModule *module_info() {
  return &xsp_ssl_auth_module;
}


int xsp_ssl_auth_init() {
  //char module_name[255];

  //if (pthread_mutex_init(&ssl_be_lock, NULL)) {
  //	xsp_err(0, "couldn't initialize mutex");
  //	goto error_exit;
  //}

  //strlcpy(module_name, "auth_ssl_", sizeof(module_name));
  //strlcat(module_name, xspSSLAuthConfig.backend, sizeof(module_name));

  //if (xsp_load_module(module_name) != 0) {
  //	xsp_err(0, "couldn't load backend: %s", xspSSLAuthConfig.backend);
  //	goto error_exit2;
  //}

  //if (ssl_be == NULL) {
  //	xsp_err(0, "backend didn't register itself: %s", xspSSLAuthConfig.backend);
  //	goto error_exit2;
  //}

  if (xsp_add_authentication_handler(&xsp_ssl_auth_handler) != 0) {
    xsp_err(0, "couldn't register SSL authentication handler");
    //goto error_exit2;
    goto error_exit;
  }
  server_pem = getenv("SERVER_PEM");
  client_name = getenv("CLIENT_NAME");

  return 0;

error_exit:
  return -1;
}

int xsp_ssl_auth_authenticate(xspConn *conn, xspCreds **ret_creds) {
  xspCreds *creds;
  //xspMsg *msg;

  //msg = xsp_conn_get_msg(conn, 0);
  //if (!msg)
  //	goto error_exit;

  // create a creds structure to hold the info we got from the DB
  creds = malloc(sizeof(xspCreds));
  if (!creds) {
    xsp_err(0, "failed to allocate credentials");
    goto error_exit;
  }

  creds->type = "SSL";
  creds->free = xsp_ssl_auth_free_credentials;
  creds->ctx = initialize_ctx(server_pem, "password");
  creds->get_user = xsp_ssl_auth_get_user;
  creds->get_email = xsp_ssl_auth_get_email;
  creds->get_institution = xsp_ssl_auth_get_institution;
  SSL_CTX_set_session_id_context(creds->ctx, (void*)&s_server_session_id_context, sizeof s_server_session_id_context);
  SSL_CTX_set_verify(creds->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

  xspConn_tcpData *tcpData = (xspConn_tcpData *)(conn->conn_private);
  int sd = tcpData->sd;

  creds->sbio = BIO_new_socket(sd, BIO_NOCLOSE);
  creds->ssl = SSL_new(creds->ctx);
  SSL_set_bio(creds->ssl, creds->sbio, creds->sbio);

  // at this point, the server should send information to the client, requesting SSL connection
  xspMsg auth_msg = {
    .version = XSP_v1,
    .type = XSP_MSG_SESS_ACK,
    .flags = 0,
    .msg_body = NULL
  };
  xsp_conn_send_msg(conn, &auth_msg, XSP_MSG_SESS_ACK);// why specify the type again?

  int r = SSL_accept(creds->ssl);
  if(r <= 0) {
    xsp_err(0, "SSL accept error, error number is: %d", r);

    int ret = SSL_get_error(creds->ssl, r);
    switch(ret) {
    case SSL_ERROR_NONE:
      xsp_err(0, "SSL_ERROR_NONE");
      break;
    case SSL_ERROR_ZERO_RETURN:
      xsp_err(0, "SSL_ERROR_ZERO_RETURN");
      break;
    case SSL_ERROR_WANT_READ:
      xsp_err(0, "SSL_ERROR_WANT_READ");
      break;
    case SSL_ERROR_WANT_WRITE:
      xsp_err(0, "SSL_ERROR_WANT_WRITE");
      break;
    case SSL_ERROR_WANT_CONNECT:
      xsp_err(0, "SSL_ERROR_WANT_CONNECT");
      break;
    case SSL_ERROR_WANT_ACCEPT:
      xsp_err(0, "SSL_ERROR_WANT_ACCEPT");
      break;
    case SSL_ERROR_WANT_X509_LOOKUP:
      xsp_err(0, "SSL_ERROR_WANT_X509_LOOKUP");
      break;
    case SSL_ERROR_SYSCALL:
      xsp_err(0, "SSL_ERROR_SYSCALL");
      break;
    case SSL_ERROR_SSL:
      xsp_err(0, "SSL_ERROR_SSL");
      break;
    default:
      xsp_err(0, "default");
    }
    char buf[256];
    ERR_error_string(ERR_get_error(), buf);
    xsp_err(0, "%s", buf);
    goto error_exit;
  }
  else {
    X509 *peer;
    char peer_CN[256];

    if(SSL_get_verify_result(creds->ssl) != X509_V_OK)
      xsp_err(0, "Certificate doesn't verify");

    /* Check the common name */
    peer = SSL_get_peer_certificate(creds->ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

    if(client_name != NULL && strcasecmp(peer_CN, client_name)) {
      xsp_err(0, "Common name doesn't match host name %s : %s", peer_CN, client_name);
      goto error_exit;
    }
  }

  *ret_creds = creds;

  //xsp_free_msg(msg);

  return 0;

error_exit:
  return -1;
}

static int xsp_ssl_auth_request_authentication(comSess *sess, xspConn *conn) {
  //TODO
  return 0;
}

//static void __xsp_rand_fill(unsigned char *buf, int length) {
//	int i;
//	for(i = 0; i < length; i++)
//		buf[i] = lrand48() % 256;
//}

static const char *xsp_ssl_auth_get_user(xspCreds *creds) {
  return "a ssl certified user";
}

static const char *xsp_ssl_auth_get_email(xspCreds *creds) {
  return "N/A";
}

static const char *xsp_ssl_auth_get_institution(xspCreds *creds) {
  return "a ssl certified institution";
}

static void xsp_ssl_auth_free_credentials(xspCreds *credentials) {
  free(credentials);
}

SSL_CTX *initialize_ctx(char *keyfile, char *password) {
  SSL_METHOD *meth;
  SSL_CTX *ctx;

  if(!bio_err) {
    /* Global system initialization*/
    SSL_library_init();
    SSL_load_error_strings();

    /* An error write context */
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  }

  /* Set up a SIGPIPE handler */
  //signal(SIGPIPE,sigpipe_handle);

  /* Create our context*/
  meth = SSLv23_method();
  ctx = SSL_CTX_new(meth);

  /* Load our keys and certificates*/
  if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
    xsp_err(0, "Can't read certificate file");

  pass = password;
  SSL_CTX_set_default_passwd_cb(ctx, password_cb);

  if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
    xsp_err(0, "Can't read key file");

  /* Load the CAs we trust*/
  server_root_pem = getenv("SERVER_ROOT");
  if(!(SSL_CTX_load_verify_locations(ctx, server_root_pem, 0)))
    xsp_err(0,"server can't read CA list");

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
  SSL_CTX_set_verify_depth(ctx,1);
#endif

  return ctx;
}

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
  if(num < strlen(pass) + 1)
    return(0);

  strcpy(buf, pass);
  return(strlen(pass));
}


















