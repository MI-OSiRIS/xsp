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
#ifndef LIBXSP_INTERFACE_H
#define LIBXSP_INTERFACE_H

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#else
//#error "Couldn't find standard integer types...including stdint.h"
#include  <stdint.h>
#endif

#include <unistd.h>

#include "xsp-proto.h"
#include "libxsp_client_common.h"

#define XSP_HOP_NATIVE 0x01

typedef void libxspSess;
typedef void libxspSecInfo;
typedef void libxspNetPath;
typedef void libxspNetPathRule;

int libxsp_init(void);
libxspSess *xsp_session();
int xsp_sess_appendchild(libxspSess *sess, char *child, unsigned int flags);
int xsp_sess_addchild(libxspSess *sess, char *parent, char *child, uint16_t flags);
int xsp_sess_set_security(libxspSess *sess, libxspSecInfo *sec, int type);

libxspSecInfo *xsp_sess_new_security(char *username, char *password, char *key1, char *key2, char *keypass);
libxspNetPath *xsp_sess_new_net_path(int action);
libxspNetPathRule *xsp_sess_new_net_path_rule(libxspNetPath *path, char *type);
int xsp_sess_set_net_path_rule_crit(libxspNetPathRule *rule, libxspNetPathRuleCrit *crit);
int xsp_sess_set_net_path_rule_eid(libxspNetPathRule *rule, void *eid, int type);
int xsp_sess_set_net_path_rule_op(libxspNetPathRule *rule, int op);

int xsp_signal_path(libxspSess *sess, libxspNetPath *path);
int xsp_signal_inf_data(libxspSess *sess);

int xsp_connect(libxspSess *sess);
int xsp_setsockopt(libxspSess *sess, int level, int optname, const void *optval, socklen_t optlen);
int xsp_getsockopt(libxspSess *sess, int level, int optname, void *optval, socklen_t *optlen);
int xsp_close(libxspSess *sess);
int xsp_close2(libxspSess *sess);
ssize_t xsp_send(libxspSess *sess, const void *buf, size_t len, int flags);
ssize_t xsp_recv(libxspSess *sess, void *buf, size_t len, int flags);
int xsp_shutdown(libxspSess *sess, int how);
int xsp_get_session_socket(libxspSess *sess);
int xsp_set_session_socket(libxspSess *sess, int new_sd);
int xsp_set_session_connected(libxspSess *sess);
int xsp_send_ping(libxspSess *sess);
int xsp_recv_ping(libxspSess *sess);
int xsp_send_msg(libxspSess *sess, const void *buf, uint64_t len, int opt_type);
int xsp_recv_msg(libxspSess *sess, void **ret_buf, uint64_t *len, int *ret_type);
int xsp_wait_ack(libxspSess *sess);
int xsp_sess_cmp(libxspSess *sess1, libxspSess *sess2);

#endif
