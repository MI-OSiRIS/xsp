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
#ifndef LIBXSP_SSH_H
#define LIBXSP_SSH_H

#include "libxsp_client_private.h"

int xsp_ssh2_setup(libxspSess *sess, char *user, char *pass, char *privkey, char *pubkey, char *keypass);
ssize_t xsp_ssh2_send(libxspSess *sess, const void *buf, size_t len, int flags);
ssize_t xsp_ssh2_recv(libxspSess *sess, void *buf, size_t len, int flags);

#endif
