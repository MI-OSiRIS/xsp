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
#ifndef XSP_PEERING_H
#define XSP_PEERING_H

#define XSP_PEER_KEEPALIVE_TO 30

typedef enum xsp_sess_peer_state_t {
	XSP_PEER_WAIT = 0x1,
} xsp_sess_peer_state;

typedef enum xsp_peer_app_message_t {
	XSP_PEER_MSG_HELLO,
	XSP_PEER_MSG_BYE
} xsp_peer_app_msg;

typedef struct xsp_peering_config_t {
	char **static_peer_list;
	int static_peer_count;
	int keepalive_timer;
	int use_unis;
} xspPeerConfig;

#endif
