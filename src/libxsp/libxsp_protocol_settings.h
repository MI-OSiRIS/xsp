#ifndef XSP_PROTOCOL_SETTINGS_H
#define XSP_PROTOCOL_SETTINGS_H

#include "libconfig.h"

typedef struct xsp_protocol_settings_t {
	config_t root;
	const char *type;
} xspProtocolSettings;

xspProtocolSettings *xsp_alloc_protocol_settings();
void xsp_free_protocol_settings(xspProtocolSettings *settings);

int xsp_protocol_settings_getval(xspProtocolSettings *settings, const char *key, char **value);
int xsp_protocol_settings_getval_int(xspProtocolSettings *settings, const char *key, int *value);
int xsp_protocol_settings_getval_bool(xspProtocolSettings *settings, const char *key, int *value);

int xsp_protocol_settings_setval(xspProtocolSettings *settings, const char *key, char *value);
int xsp_protocol_settings_setval_int(xspProtocolSettings *settings, const char *key, int value);
int xsp_protocol_settings_setval_bool(xspProtocolSettings *settings, const char *key, int value);

#endif
