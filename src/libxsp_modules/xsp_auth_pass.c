#include <stdlib.h>
#include <string.h>

#include "config.h"

#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#endif

#include "xsp_modules.h"
#include "xsp_session.h"
#include "xsp_conn.h"
#include "xsp_auth.h"
#include "xsp_auth_pass.h"
#include "xsp_logger.h"
#include "xsp_config.h"

#include "compat.h"

xspModule *module_info();
static int xsp_pass_auth_init();
static int xsp_pass_auth_authenticate(xspConn *conn, xspCreds **ret_creds);
static int xsp_pass_auth_request_authentication(comSess *sess, xspConn *conn);
static const char *xsp_pass_auth_get_user(xspCreds *creds);
static const char *xsp_pass_auth_get_email(xspCreds *creds);
static const char *xsp_pass_auth_get_institution(xspCreds *creds);
static void xsp_pass_auth_free_credentials(xspCreds *credentials);
static int __xsp_sanity_check_username(const char *username, int length);
static int __xsp_hash_password(const char *pass, int pass_len, const unsigned char *nonce, unsigned char *ret_hash);
static void __xsp_rand_fill(unsigned char *buf, int length);

static xspPassBackend *pass_be = NULL;
static pthread_mutex_t pass_be_lock;

static xspAuthenticationHandler xsp_pass_auth_handler = {
	.name = "PASS",
	.authenticate = xsp_pass_auth_authenticate,
	.request_authentication = xsp_pass_auth_request_authentication,
};

static xspModule xsp_pass_auth_module = {
	.desc = "Password Authentication Module",
	.dependencies = "",
	.init = xsp_pass_auth_init
};

xspModule *module_info() {
	return &xsp_pass_auth_module;
}

struct xsp_pass_auth_config_t {
	char *backend;
};

static struct xsp_pass_auth_config_t xspPassAuthConfig = {
	.backend = "file",
};

static void xsp_pass_auth_read_config() {
	char *str_val;
	const xspSettings *settings;
	
	settings = xsp_main_settings();
	if (xsp_settings_get_2(settings, "pass_auth", "backend", &str_val) == 0) {
		xspPassAuthConfig.backend = str_val;
	}
}

int xsp_pass_auth_init() {
	char module_name[255];

	xsp_pass_auth_read_config();

	if (pthread_mutex_init(&pass_be_lock, NULL)) {
		xsp_err(0, "couldn't initialize mutex");
		goto error_exit;
	}

	strlcpy(module_name, "auth_pass_", sizeof(module_name));
	strlcat(module_name, xspPassAuthConfig.backend, sizeof(module_name));

	if (xsp_load_module(module_name) != 0) {
		xsp_err(0, "couldn't load backend: %s", xspPassAuthConfig.backend);
		goto error_exit2;
	}

	if (pass_be == NULL) {
		xsp_err(0, "backend didn't register itself: %s", xspPassAuthConfig.backend);
		goto error_exit2;
	}

	if (xsp_add_authentication_handler(&xsp_pass_auth_handler) != 0) {
		xsp_err(0, "couldn't register PASS authentication handler");
		goto error_exit2;
	}
	return 0;

error_exit2:
	pthread_mutex_destroy(&pass_be_lock);
error_exit:
	return -1;
}

int xsp_set_pass_backend(xspPassBackend *be) {
	pthread_mutex_lock(&pass_be_lock);
	{
		pass_be = be;
	}
	pthread_mutex_unlock(&pass_be_lock);

	return 0;
}

static int __xsp_hash_password(const char *pass, int pass_len, const unsigned char *nonce, unsigned char *ret_hash) {
	unsigned char buf[SHA_DIGEST_LENGTH];
	int i;

	SHA1_wrapper((unsigned char *) pass, pass_len, buf);

	for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
		buf[i] ^= nonce[i];
	}

	SHA1_wrapper(buf, SHA_DIGEST_LENGTH, ret_hash);

	return 0;
}

static void __xsp_rand_fill(unsigned char *buf, int length) {
	int i;
	for(i = 0; i < length; i++)
		buf[i] = lrand48() % 256;
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

static int xsp_pass_auth_request_authentication(comSess *sess, xspConn *conn) {
	unsigned char hash[SHA_DIGEST_LENGTH];
	const char *username;
	xspPassUserInfo *ui;
	xspAuthToken token, *ret_token;
	xspMsg *msg;

	username = sess->credentials->get_user(sess->credentials);

	ui = pass_be->get_user_info(username);
	if (!ui) {
		xsp_err(0, "couldn't lookup user info for %s", username);
		goto error_exit;
	}

	token.token = ui->username;
	token.token_length = strlen(ui->username);

	xspMsg auth_msg = {
		.version = sess->version,
		.type = XSP_MSG_AUTH_TOKEN,
		.flags = 0,
		.msg_body = &token
	};
	if (xsp_conn_send_msg(conn, &auth_msg, XSP_OPT_AUTH_TOK) < 0) {
		xsp_err(0, "couldn't send user name");
		goto error_exit2;
	}

	msg = xsp_conn_get_msg(conn, 0);
	if (!msg) {
		xsp_err(0, "received no response");
		goto error_exit2;
	}

	ret_token = msg->msg_body;

	if (ret_token->token_length != SHA_DIGEST_LENGTH) {
		xsp_err(0, "received invalid response");
		goto error_exit3;
	}

	__xsp_hash_password(ui->password, strlen(ui->password), ret_token->token, hash);

	token.token = hash;
	token.token_length = SHA_DIGEST_LENGTH;

	xspMsg auth_msg2 = {
                .version = sess->version,
                .type = XSP_MSG_AUTH_TOKEN,
                .flags = 0,
		.msg_body = &token
        };
	if (xsp_conn_send_msg(conn, &auth_msg2, XSP_OPT_AUTH_TOK) < 0) {
		xsp_err(0, "couldn't send password hash");
		goto error_exit3;
	}

	return 0;

error_exit3:
	xsp_free_msg(msg);
error_exit2:
	xsp_free_pass_user_info(ui);
error_exit:
	return -1;
}

int xsp_pass_auth_authenticate(xspConn *conn, xspCreds **ret_creds) {
	xspCreds *creds;
	xspMsg *msg1, *msg2;
	xspAuthToken *recv_token;
	xspAuthToken send_token;
	unsigned char nonce[SHA_DIGEST_LENGTH];
	unsigned char hash[SHA_DIGEST_LENGTH];
	char username[255];
	xspPassUserInfo *ui;

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

	// send a nonce to the user
	__xsp_rand_fill(nonce, SHA_DIGEST_LENGTH);

	bzero(&send_token, sizeof(xspAuthToken));
	send_token.token = nonce;
	send_token.token_length = SHA_DIGEST_LENGTH;
	
	xspMsg auth_msg = {
                .version = msg1->version,
                .type = XSP_MSG_AUTH_TOKEN,
                .flags = 0,
		.msg_body = &send_token
        };
	xsp_conn_send_msg(conn, &auth_msg, XSP_OPT_AUTH_TOK);
	
	// get the password hash from the user
	msg2 = xsp_conn_get_msg(conn, 0);
	if (!msg2) {
		xsp_err(0, "no password hash received");
		goto error_exit3;
	}

	// sanity check their response
	if (msg2->type != XSP_MSG_AUTH_TOKEN) {
		xsp_err(0, "recieved invalid password response");
		goto error_exit4;
	}

	recv_token = msg2->msg_body;

	if (recv_token->token_length != SHA_DIGEST_LENGTH) {
		xsp_err(0, "recieved invalid password hash");
		goto error_exit4;
	}

	// grab the info for the specified
	ui = pass_be->get_user_info(username);
	if (!ui) {
		xsp_err(0, "get user info for %s failed", username);
		goto error_exit2;
	}

	__xsp_hash_password(ui->password, strlen(ui->password), nonce, hash);

	if (ui->activated != 1) {
		xsp_err(0, "user %s has not been activated", username);
		goto error_exit5;
	}

	// check the password
	if (memcmp(hash, recv_token->token, SHA_DIGEST_LENGTH) != 0) {
		xsp_err(0, "password authentication for user %s failed", username);
		goto error_exit5;
	}

	// create a creds structure to hold the info we got from the DB
	creds = malloc(sizeof(xspCreds));
	if (!creds) {
		xsp_err(0, "failed to allocate credentials");
		goto error_exit5;
	}

	creds->type = "PASS";
	creds->get_user = xsp_pass_auth_get_user;
	creds->get_email = xsp_pass_auth_get_email;
	creds->get_institution = xsp_pass_auth_get_institution;
	creds->free = xsp_pass_auth_free_credentials;
	creds->private = ui;

	*ret_creds = creds;

	xsp_free_msg(msg1);
	xsp_free_msg(msg2);

	return 0;

error_exit5:
	xsp_free_pass_user_info(ui);
error_exit4:
	xsp_free_msg(msg2);
error_exit3:
	//free(username);
error_exit2:
	xsp_free_msg(msg1);
error_exit:
	return -1;
}

static void xsp_pass_auth_free_credentials(xspCreds *credentials) {
	xspPassUserInfo *ui = (xspPassUserInfo *) credentials->private;

	xsp_free_pass_user_info(ui);
	free(credentials);
}

xspPassUserInfo *xsp_alloc_pass_user_info() {
	xspPassUserInfo *ui;

	ui = malloc(sizeof(xspPassUserInfo));
	if (!ui)
		goto error_exit;

	bzero(ui, sizeof(xspPassUserInfo));

	return ui;

error_exit:
	return NULL;
}

void xsp_free_pass_user_info(xspPassUserInfo *ui) {
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

static const char *xsp_pass_auth_get_user(xspCreds *creds) {
	xspPassUserInfo *ui = creds->private;
	return ui->username;
}

static const char *xsp_pass_auth_get_email(xspCreds *creds) {
	xspPassUserInfo *ui = creds->private;
	return ui->email;
}

static const char *xsp_pass_auth_get_institution(xspCreds *creds) {
	xspPassUserInfo *ui = creds->private;
	return ui->institution;
}
