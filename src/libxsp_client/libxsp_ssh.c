#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

int __ssh2_setup_try_agent(libxspSess *sess, char *user) {
	int rc;
	struct libssh2_agent_publickey *identity, *prev_identity = NULL;
	
	/* Connect to the ssh-agent */ 
	sess->agent = libssh2_agent_init(sess->ssh_sess);
	
	if (!sess->agent) {
		d_printf("ssh2_try_agent(): Failure initializing ssh-agent support\n");
		return FALSE;
	}
	if (libssh2_agent_connect(sess->agent)) {
		d_printf("ssh2_try_agent(): Failure connecting to ssh-agent\n");
		return FALSE;
	}
	if (libssh2_agent_list_identities(sess->agent)) {
		d_printf("ssh2_try_agent(): Failure requesting identities to ssh-agent\n");
		return FALSE;
	}
	while (1) {
		rc = libssh2_agent_get_identity(sess->agent, &identity, prev_identity);

		if (rc == 1)
			break;
		if (rc < 0) {
			d_printf("ssh2_try_agent(): Failure obtaining identity from ssh-agent support\n");
			break;
		}
		if (libssh2_agent_userauth(sess->agent, user, identity)) {

			d_printf("ssh2_try_agent(): Authentication with username %s and "
				 "public key %s failed!\n",
				 user, identity->comment);
		} else {
			d_printf("ssh2_try_agent(): Authentication with username %s and "
				 "public key %s succeeded!\n",
				 user, identity->comment);
			return TRUE;
		}
		prev_identity = identity;
	}

	return FALSE;
}

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

	if (!authdone)
		authdone = __ssh2_setup_try_agent(sess, sec->username);

	if (!authdone && (auth & AUTH_PASSWORD) && user && pass) {
		if (libssh2_userauth_password(sess->ssh_sess, sec->username, sec->password)) {
			
			d_printf("ssh2_setup(): authentication by password failed\n");
		}
		d_printf("ssh2_setup(): authentication by password succeeded\n");
		authdone = TRUE;
	}
	
	if (!authdone && (auth & AUTH_PUBLICKEY) && sec->key1 && sec->key2) {
		ret = libssh2_userauth_publickey_fromfile(sess->ssh_sess, sec->username, sec->key1,
							  sec->key2, sec->keypass);
		if (ret) {
			char *errmsg;
			int errlen;
			libssh2_session_last_error(sess->ssh_sess, &errmsg, &errlen, 0); 
			d_printf("ssh2_setup(): authentication by public key failed (%d): %s\n", ret, errmsg);
		}
		d_printf("ssh2_setup(): authentication by public key succeeded\n");
		authdone = TRUE;
	}
	
	if (!authdone) {
		d_printf("ssh2_setup(): no supported authentication methods found!\n");
		goto error_exit;
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

ssize_t __ssh2_chan_read(libxspSess *sess, void *buf, size_t len, int flags) {
	int amt_read;
	int ret;
	int retries;

	amt_read = 0;
	retries = MAX_RECV_RETRIES;

	while (retries) {
		ret = libssh2_channel_read(sess->ssh_chan, buf, len);
		if (ret < 0) {
			if (ret == LIBSSH2_ERROR_EAGAIN) {
				retries--;
				d_printf("ssh2_chan_read(): EAGAIN\n");
				usleep(5000);
			} else {
				d_printf("ssh2_chan_read(): read error\n");
				return ret;
			}

		}
		else if (ret > 0) {
			d_printf("ssh2_chan_read(): received %d bytes\n", ret);
			amt_read += ret;
			if (amt_read == len) {
				return amt_read;
			}

		}
		else {
			d_printf("ssh2_chan_read(): session closed\n");
			return ret;
		}
	}
	return ret;
}

ssize_t xsp_ssh2_recv(libxspSess *sess, void *buf, size_t len, int flags) {
	int ret;
	int amt_read;
	int done;
	fd_set fds;

	FD_ZERO(&fds);

	amt_read = 0;
	done = FALSE;

	d_printf("in recv for %d bytes\n", len);

	ret = __ssh2_chan_read(sess, buf, len, flags);
	if (ret < (int)len) {
		while (!done) {
			FD_SET(sess->sock, &fds);
			
			d_printf("ssh2_recv: going into select\n");
			
			ret = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
			
			if (ret < 0) {
				d_printf("ssh2_recv(): select error (%d)\n", ret);
				done = TRUE;
				continue;
			}
			
			if (FD_ISSET(sess->sock, &fds)) {
				amt_read = __ssh2_chan_read(sess, buf, len, flags);
				if (amt_read == len) {
					done = TRUE;
				}
			}
		}
	}
	
	return ret;
}
