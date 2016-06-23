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
#include "libxsp.h"
#include "xsp_conn.h"
#include "xsp_debug.h"

#include "globus_common.h"
#include "globus_gss_assist.h"

static gss_cred_id_t srv_cred_handle;
static int globus_enabled;

typedef struct xsp_globus_credentials_t {
	gss_ctx_id_t gss_context;
	gss_cred_id_t delegated_credential;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	char *peer_name;
	char *username;
} xspGlobusCreds;

xspGlobusCreds *xsp_globus_alloc_globuscreds();
int xsp_globus_get_token(void *arg, void **token, size_t *token_length);
int xsp_globus_send_token(void *arg, void *token, size_t token_length);

int xsp_globus_init() {
	OM_uint32 major, minor;
	
	major = globus_module_activate(GLOBUS_COMMON_MODULE);
	
	if (major != GLOBUS_SUCCESS) {
		xsp_debug(0, "xsp_globus_init(): couldn't load globus module");
		goto error_exit;
	}

	major = globus_gss_assist_acquire_cred(&minor, GSS_C_BOTH, &srv_cred_handle);
	
	if (major != GSS_S_COMPLETE) {
		xsp_debug(0, "xsp_globus_init(): failed to obtain credentials");
		goto error_exit2;
	}

	globus_enabled = 1;

	return 0;

error_exit2:
	globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
error_exit:
	globus_enabled = 0;
	return -1;
}

xspGlobusCreds *xsp_globus_alloc_globuscreds() {
	xspGlobusCreds *new_creds;

	new_creds = malloc(sizeof(xspGlobusCreds));
	if (!new_creds)
		return NULL;

	new_creds->gss_context = GSS_C_NO_CONTEXT;
	new_creds->delegated_credential = GSS_C_NO_CREDENTIAL;
	new_creds->major_status = 0;
	new_creds->minor_status = 0;
	new_creds->peer_name = NULL;
	new_creds->username = NULL;

	return new_creds;
}

int xsp_globus_authorize(xspConn *conn, void **ret_creds) {
	int token_status;
	OM_uint32 ret_flags;
	xspGlobusCreds *creds;

	if (globus_enabled == 0) {
		return -1;
	}

	creds = xsp_globus_alloc_globuscreds();
	if (!creds)
		goto error_exit;

	ret_flags = 0;

	creds->major_status = globus_gss_assist_accept_sec_context(
			&(creds->minor_status),
			&(creds->gss_context),
			srv_cred_handle,
			&(creds->peer_name),
			&ret_flags,
			NULL,
			&token_status,
			&(creds->delegated_credential),
			xsp_globus_get_token,
			(void *) conn,
			xsp_globus_send_token, 
			(void *) conn);

	if (creds->major_status != GSS_S_COMPLETE) {
		xsp_debug(5, "Globus authentication failed for: %s", conn->description);
		goto error_exit;
	}

	creds->major_status = globus_gss_assist_gridmap(creds->peer_name, &(creds->username));
	if (creds->major_status != GSS_S_COMPLETE) {
		xsp_debug(5, "Couldn't locate a user(%s) for connection: %s", creds->peer_name, conn->description);
		goto error_exit;
	}

	*ret_creds = creds;

	return 0;

error_exit:
	return -1;
}

int xsp_globus_request_authorization(xspSess *sess, xspConn *new_conn) {
	OM_uint32 ret_flags, token_status;
	ret_flags = 0;
	token_status = 0;
	xspGlobusCreds *creds;

	creds = sess->auth_info;

	creds->major_status = globus_gss_assist_init_sec_context(
			&(creds->minor_status),
			creds->delegated_credential,
			&(creds->gss_context),
			NULL,
			GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG,
			&ret_flags,
			&token_status,
			xsp_globus_get_token,
			(void *) new_conn,
			xsp_globus_send_token,
			(void *) new_conn);

	if (creds->major_status != GSS_S_COMPLETE) {
		xsp_debug(5, "couldn't authenticate using delegated credentials");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

int xsp_globus_send_token(void *arg, void *token, size_t token_length) {
    xspConn *conn = arg;
    xspAuthToken xsp_token;

    xsp_token.token_length = token_length;
    xsp_token.token = token;

    conn->send_msg(conn, XSP_MSG_AUTH_TOKEN, &xsp_token);

    return 0;
}

int xsp_globus_get_token(void *arg, void **token, size_t *token_length) {
	xspConn *conn = arg;
	xspAuthToken *xsp_token;
	xspMsg *msg;

	msg = conn->get_msg(conn, 0);
	if (!msg)
		goto error_exit;

	if (msg->type != XSP_MSG_AUTH_TOKEN)
		goto error_exit2;

	xsp_token = msg->msg_body;

	*token_length = xsp_token->token_length;

	*token = xsp_token->token;

	free(xsp_token);
	free(msg);

	return 0;

error_exit2:
	xsp_free_msg(msg);
error_exit:
	return -1;
}
