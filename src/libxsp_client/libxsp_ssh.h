#ifndef LIBXSP_SSH_H
#define LIBXSP_SSH_H

#include "libxsp_client_private.h"

int xsp_ssh2_setup(libxspSess *sess, char *user, char *pass, char *privkey, char *pubkey, char *keypass);
ssize_t xsp_ssh2_send(libxspSess *sess, const void *buf, size_t len, int flags);
ssize_t xsp_ssh2_recv(libxspSess *sess, void *buf, size_t len, int flags);

#endif
