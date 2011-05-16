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

int xsp_get_authentication_handler(const char *name) {
	int i;

	for(i = 0;  i < 255; i++) {
		if (auth_handlers[i] != NULL) {
			if (strcasecmp(auth_handlers[i]->name, name) == 0)
				return i;
		}
	}

	return -1;
}

int xsp_authenticate_connection(xspConn *conn, const char *auth_type, xspCreds **ret_creds) {
	int num;
	xspMsg *msg;

	num = xsp_get_authentication_handler(auth_type);
	if (num < 0) {
		xsp_err(1, "bad authentication handler: \"%s\"", auth_type);
		goto error_exit;
	}

	return auth_handlers[num]->authenticate(conn, ret_creds);

error_exit:
	return -1;
}

int xsp_request_authentication(xspSess *sess, xspConn *new_conn, const char *auth_name) {
	int num;
	xspAuthType auth_type;

	num = xsp_get_authentication_handler(auth_name);
	if (num < 0) {
		xsp_err(1, "bad authentication handler: \"%s\"", auth_name);
		return -1; // XXX: fixme
	}

	strlcpy(auth_type.name, auth_name, XSP_AUTH_NAME_LEN);

	if (!xsp_conn_send_msg(new_conn, XSP_MSG_AUTH_TYPE, &auth_type)) {
		xsp_err(1, "send msg failed");
		return -1;
	}

	return auth_handlers[num]->request_authentication(sess, new_conn);
}
