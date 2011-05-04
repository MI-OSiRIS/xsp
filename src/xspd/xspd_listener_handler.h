#ifndef XSPD_LISTENER_HANDLER_H
#define XSPD_LISTENER_HANDLER_H

#include "xspd_listener.h"

int xspd_listener_handler_init();
int xspd_listener_handler_register_listener(xspdListener *listener);
void xspd_listener_handler_unregister_listener(const char *listener_id);
void __xspd_listener_handler_unregister_listener(xspdListener *listener);
int xspd_listener_handler_start_listener(const char *listener_id);
int xspd_listener_handler_stop_listener(const char *listener_id);
int xspd_listener_handler_shutdown_listener(const char *listener_id);
xspdListener *xspd_listener_handler_lookup_listener(const char *listener_id);

#endif
