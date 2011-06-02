#include <stdio.h>
#include <stdlib.h>

#include "libxsp_ssh.h"
#include "libxsp_client_private.h"
#include "libssh2.h"

enum {
	FALSE = 0,
	TRUE = 1
};

enum {
	AUTH_NONE = 0,
	AUTH_PASSWORD,
	AUTH_PUBLICKEY
};

#define MAX_RECV_RETRIES 5

int xsp_ssh2_setup(libxspSess *sess, char *user, char *pass, char *privkey, char *pubkey, char *keypass) {
	int ret;
	int auth = AUTH_NONE;
	const char *fingerprint;
	char       *userauthlist;
	int authdone = FALSE;

	libxspSecInfo *sec;
	if (sess->sec_info)
		sec = sess->sec_info;
	else {
		libxspSecInfo new_sec;
		new_sec.username = user;
		new_sec.password = pass;
		new_sec.key1 = pubkey;
		new_sec.key2 = privkey;
		new_sec.keypass = keypass;
		
		sec = &new_sec;
	}
	
	d_printf("ssh2_setup() sec_info: uname: %s, pass %s, privkey: %s, pubkey: %s, keypass: %s\n",
		 sec->username, sec->password, sec->key1, sec->key2, sec->keypass);
	
	sess->ssh_sess = libssh2_session_init();
	if (!sess->ssh_sess) {
		d_printf("ssh2_setup(): could not init ssh2 session\n");
		goto error_exit;
	}

	ret = libssh2_session_startup(sess->ssh_sess, sess->sock);
	if (ret) {
		d_printf("ssh2_setup(): could not start ssh2 session\n");
		goto error_exit;
	}

	fingerprint = libssh2_hostkey_hash(sess->ssh_sess,
					   LIBSSH2_HOSTKEY_HASH_MD5);

	userauthlist = libssh2_userauth_list(sess->ssh_sess,
					     user,
					     strlen(user));
	
	if (!userauthlist) {
		if (libssh2_userauth_authenticated(sess->ssh_sess)) {
			d_printf("ssh2_setup(): agent accepted SSH_AUTH_NONE");
			authdone = TRUE;
		} else {
			d_printf("ssh2_setup(): SSH2 get authlist failed");
			goto error_exit;
		}
	}

	d_printf("ssh2_setup(): authentication methods: %s\n", userauthlist);
	if (strstr(userauthlist, "password"))
		auth |= AUTH_PASSWORD;
	if (strstr(userauthlist, "publickey"))
		auth |= AUTH_PUBLICKEY;

	if (!authdone) {
		if ((auth & AUTH_PASSWORD) && user && pass) {
			if (libssh2_userauth_password(sess->ssh_sess, sec->username, sec->password)) {
				
				d_printf("ssh2_setup(): authentication by password failed\n");
				goto error_exit;
			}
			d_printf("ssh2_setup(): authentication by password succeeded\n");
		} 
		else if (auth & AUTH_PUBLICKEY) {
			ret = libssh2_userauth_publickey_fromfile(sess->ssh_sess, sec->username, sec->key1,
								  sec->key2, sec->keypass);
			if (ret) {
				char *errmsg;
				int errlen;
				libssh2_session_last_error(sess->ssh_sess, &errmsg, &errlen, 0); 
				d_printf("ssh2_setup(): authentication by public key failed (%d): %s\n", ret, errmsg);
				goto error_exit;
			}
			d_printf("ssh2_setup(): authentication by public key succeeded\n");
		} 
		else {
			d_printf("ssh2_setup(): no supported authentication methods found!\n");
			goto error_exit;
		}
	}
	
	sess->ssh_chan = libssh2_channel_open_session(sess->ssh_sess);
	if (!sess->ssh_chan) {
		d_printf("ssh2_setup(): SSH2 channel open failed");
		goto error_exit;
	}

	ret = libssh2_channel_subsystem(sess->ssh_chan, "xsp");
	if (ret) {
		d_printf("ssh2_sess(): Unable to request xsp subsystem");
		goto error_exit;
	}
	
	libssh2_channel_set_blocking(sess->ssh_chan, 0);
	
	libssh2_channel_handle_extended_data2
		(sess->ssh_chan,
		 LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);

	return 0;

 error_exit:
	return -1;
}

ssize_t xsp_ssh2_send(libxspSess *sess, const void *buf, size_t len, int flags) {
	int done = FALSE;
	int ret;

	/* operating on a non-blocking socket */
	while (!done) {
		ret = libssh2_channel_write(sess->ssh_chan, (char *)buf, len);
		if (ret < 0 || ret != (int)len) {
			if (ret == LIBSSH2_ERROR_EAGAIN) {
				/* not done; sleep and try again */
				usleep(1000);   /* 1000 micro-seconds */
				continue;
			}
		}
		done = TRUE;
        }
	
	if (ret == 0) {
		d_printf("ssh2_send(): session closed\n");
	}
	else if (ret > 0) {
		d_printf("ssh2_send(): sent %d bytes\n", len);
	}
	
	return ret;
}

ssize_t xsp_ssh2_recv(libxspSess *sess, void *buf, size_t len, int flags) {
	int ret;
	int amt_read = 0;
	int done = FALSE;
	int retries = MAX_RECV_RETRIES;;

	while (!done && retries) {
		ret = libssh2_channel_read(sess->ssh_chan, buf, len);
		if (ret == 1) {
			d_printf("VERSION: %d\n", buf);
		}
		if (ret < 0) {
			if (ret == LIBSSH2_ERROR_EAGAIN) {
				retries--;
				d_printf("ssh2_recv(): EAGAIN\n");
				usleep(100000);
			} else {
				d_printf("ssh2_recv(): read error\n");
				break;
			}
			
		}
		else if (ret > 0) {
			d_printf("ssh2_recv(): received %d bytes\n", ret);
			amt_read += ret;
			if (amt_read == len)
				done = TRUE;
		}
		else {
			d_printf("ssh2_recv(): session closed\n");
			break;
		}
	}
	
	return ret;
}
