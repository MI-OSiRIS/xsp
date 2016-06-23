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

#include "xsp_conn.h"
#include "xsp_auth.h"
#include "xsp_logger.h"
#include "xsp_settings.h"
#include "xsp_default_settings.h"

#include "compat.h"

static char *default_authentication[] = { "ANON" };
static int default_authentication_count = 1;

static xspAuthenticationHandler *auth_handlers[255];
static char auth_list[255 * (XSP_AUTH_NAME_LEN + 1) + 1];

int __xsp_get_authentication_handler_index(const char *name);

int xsp_add_authentication_handler(xspAuthenticationHandler *handler) {
	uint8_t i;

	for(i = 0;  i < 255; i++) {
		if (auth_handlers[i] != NULL) {
			if (strcasecmp(auth_handlers[i]->name, handler->name) == 0) {
				break;
			}
		} else {
			break;
		}
	}

	if (i == 255) {
		return -1;
	}

	auth_handlers[i] = handler;

	strlcat(auth_list, handler->name, sizeof(auth_list));
	strlcat(auth_list, " ", sizeof(auth_list));

	return 0;

}

int xsp_authentication_init() {
	return 0;
}

xspAuthenticationHandler *xsp_get_authentication_handler(const char *name) {
	int i = __xsp_get_authentication_handler_index(name);
	if (i >= 0)
		return auth_handlers[i];
	else
		return NULL;
}

int __xsp_get_authentication_handler_index(const char *name) {
	int i;

	for(i = 0;  i < 255; i++) {
		if (auth_handlers[i] != NULL) {
			if (strcasecmp(auth_handlers[i]->name, name) == 0)
				return i;
		}
	}

	return -1;
}

int xsp_authenticate_connection(xspConn *conn, xspMsg *msg, xspCreds **ret_creds) {
	int num;
	char *auth_type;

	switch (msg->version) {
        case XSP_v0:
		auth_type = msg->msg_body;
		break;
	case XSP_v1:
		{
			xspBlock **blocks;
			int count;
			xsp_block_list_find((xspBlockList*)msg->msg_body, XSP_OPT_AUTH_TYP, &blocks, &count);
			// XXX: we can have more than one auth type in the auth request
			// just pick the first one for now
			if (count > 0)
				auth_type = blocks[0]->data;
			else {
				xsp_err(1, "no AUTH TYPE option block found");
				goto error_exit;
			}
		}
		break;
	default:
                xsp_warn(0, "unknown session open msg version");
                break;
        }


	num = __xsp_get_authentication_handler_index(auth_type);
	if (num < 0) {
		xsp_err(1, "bad authentication handler: \"%s\"", auth_type);
		goto error_exit;
	}

	return auth_handlers[num]->authenticate(conn, ret_creds);

error_exit:
	return -1;
}

int xsp_request_authentication(comSess *sess, xspConn *new_conn, const char *auth_name) {
	int num;
	xspAuthType auth_type;

	num = __xsp_get_authentication_handler_index(auth_name);
	if (num < 0) {
		xsp_err(1, "bad authentication handler: \"%s\"", auth_name);
		return -1; // XXX: fixme
	}

	strlcpy(auth_type.name, auth_name, XSP_AUTH_NAME_LEN);

	xspMsg msg = {
		.version = sess->version,
		.type = XSP_MSG_AUTH_TYPE,
		.flags = 0,
		.msg_body = &auth_type
	};
	if (!xsp_conn_send_msg(new_conn, &msg, XSP_OPT_AUTH_TYP)) {
		xsp_err(1, "send msg failed");
		return -1;
	}

	return auth_handlers[num]->request_authentication(sess, new_conn);
}
