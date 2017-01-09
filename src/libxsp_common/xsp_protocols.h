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
#ifndef XSP_PROTOCOLS_H
#define XSP_PROTOCOLS_H

#include "xsp_conn.h"
#include "xsp_listener.h"

/*
 *  int xsp_protocol_init():
 *      This function initializes the protocol subsystem.
 */
int xsp_protocol_init();

/*
 * This structure is registered with the protocol subsystem to allow a new protocol to be added
 * name: Plaintext name for the protocol(e.g. TCP, MTCP, UDT).
 * connect: Function pointer to the specified protocols connect routine. It
 *          returns a connection structure for the connection created.
 */
typedef struct xsp_protocol_handler_t {
  char *name;
  xspConn *(*connect)(const char *hostname, xspSettings *settings);
  xspListener *(*setup_listener) (const char *listener_id, xspSettings *settings, int one_shot, listener_cb callback, void *arg);
  const xspSettingDesc *(*get_settings) (int *desc_count);
} xspProtocolHandler;

/*
 *  int xsp_add_protocol(xspProtocolHandler *handler):
 *      This function adds the given protocol handler to the list of protocols. It returns 0 if successful.
 */
int xsp_add_protocol_handler(xspProtocolHandler *handler);

/*
 *  xspConn *xsp_protocol_connect_host(const char *hostname, const char *protocol, xspSettings *settings);
 *      This function connects to the specified host using the specified
 *      protocol with the specified protocol settings. It returns a pointer to
 *      the connection created. If the function couldn't connect, it returns
 *      NULL.
 */
xspConn *xsp_protocol_connect_host(const char *hostname, const char *protocol, xspSettings *settings);

/*
 *  const char **xsp_get_protocol_list(int *num_protcols):
 *      This function returns the list of protocol handlers registered.
 */
char **xsp_get_protocol_list(int *num_protocols);

xspListener *xsp_protocol_setup_listener(const char *listener_id, const char *protocol, xspSettings *settings, int one_shot, listener_cb cb, void *arg);

const xspSettingDesc *xsp_protocol_get_available_settings (const char *protocol, int *desc_count);

#endif
