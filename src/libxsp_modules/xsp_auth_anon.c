#include <string.h>
#include <stdlib.h>

#include "xsp_auth.h"
#include "xsp_auth_anon.h"
#include "xsp_modules.h"

int xsp_auth_anon_authenticate(xspConn *conn, xspCreds **ret_creds);
int xsp_auth_anon_request_authentication (xspSess *sess, xspConn *conn);
const char *xsp_auth_anon_get_value(xspCreds *credentials);
void xsp_auth_anon_free_credentials(xspCreds *credentials);

static xspAuthenticationHandler xsp_auth_anon_handler = {
	.authenticate = xsp_auth_anon_authenticate,
	.request_authentication = xsp_auth_anon_request_authentication,
	.name = "ANON",
};

static xspModule xsp_auth_anon_module = {
	.desc = "Anonymous Authentication Module",
	.dependencies = "",
	.init = xsp_auth_anon_init
};

xspModule *module_info() {
	return &xsp_auth_anon_module;
}

int xsp_auth_anon_init() {
	return xsp_add_authentication_handler(&xsp_auth_anon_handler);
}

const char *xsp_auth_anon_get_value(xspCreds *credentials) {

	return "";
}

void xsp_auth_anon_free_credentials(xspCreds *credentials) {
	free(credentials);
}

int xsp_auth_anon_request_authentication (xspSess *sess, xspConn *conn) {
	return 0;
}

int xsp_auth_anon_authenticate(xspConn *conn, xspCreds **ret_creds) {
	xspCreds *creds;

	creds = malloc(sizeof(xspCreds));
	if (!creds)
		goto error_exit;

	creds->type = "ANON";
	creds->private = NULL;
	creds->get_user = xsp_auth_anon_get_value;
	creds->get_email = xsp_auth_anon_get_value;
	creds->get_institution = xsp_auth_anon_get_value;
	creds->free = xsp_auth_anon_free_credentials;


	*ret_creds = creds;

	return 0;

error_exit:
	return -1;
}
