#ifndef XSP_LISTENER_HANDLER_H
#define XSP_LISTENER_HANDLER_H

#include "xsp_listener.h"

int xsp_listener_handler_init();
int xsp_listener_handler_register_listener(xspListener *listener);
void xsp_listener_handler_unregister_listener(const char *listener_id);
void __xsp_listener_handler_unregister_listener(xspListener *listener);
int xsp_listener_handler_start_listener(const char *listener_id);
int xsp_listener_handler_stop_listener(const char *listener_id);
int xsp_listener_handler_shutdown_listener(const char *listener_id);
xspListener *xsp_listener_handler_lookup_listener(const char *listener_id);

#endif
