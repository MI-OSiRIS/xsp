#ifndef XSPD_PROTOCOLS_H
#define XSPD_PROTOCOLS_H

#include "xspd_conn.h"
#include "xspd_listener.h"

/*
 *  int xspd_protocol_init():
 *      This function initializes the protocol subsystem.
 */
int xspd_protocol_init();

/*
 * This structure is registered with the protocol subsystem to allow a new protocol to be added
 * name: Plaintext name for the protocol(e.g. TCP, MTCP, UDT).
 * connect: Function pointer to the specified protocols connect routine. It
 *          returns a connection structure for the connection created.
 */
typedef struct xspd_protocol_handler_t {
	char *name;
	xspdConn *(*connect)(const char *hostname, xspdSettings *settings);
	xspdListener *(*setup_listener) (const char *listener_id, xspdSettings *settings, int one_shot, listener_cb callback, void *arg);
	const xspdSettingDesc *(*get_settings) (int *desc_count);
} xspdProtocolHandler;

/*
 *  int xspd_add_protocol(xspdProtocolHandler *handler):
 *      This function adds the given protocol handler to the list of protocols. It returns 0 if successful.
 */
int xspd_add_protocol_handler(xspdProtocolHandler *handler);

/*
 *  xspdConn *xspd_protocol_connect_host(const char *hostname, const char *protocol, xspdSettings *settings);
 *      This function connects to the specified host using the specified
 *      protocol with the specified protocol settings. It returns a pointer to
 *      the connection created. If the function couldn't connect, it returns
 *      NULL.
 */
xspdConn *xspd_protocol_connect_host(const char *hostname, const char *protocol, xspdSettings *settings);

/*
 *  const char **xspd_get_protocol_list(int *num_protcols):
 *      This function returns the list of protocol handlers registered.
 */
char **xspd_get_protocol_list(int *num_protocols);

xspdListener *xspd_protocol_setup_listener(const char *listener_id, const char *protocol, xspdSettings *settings, int one_shot, listener_cb cb, void *arg);

const xspdSettingDesc *xspd_protocol_get_available_settings (const char *protocol, int *desc_count);

#endif
