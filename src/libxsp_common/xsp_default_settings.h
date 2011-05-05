#ifndef XSP_DEFAULT_SETTINGS_H
#define XSP_DEFAULT_SETTINGS_H

#include "xsp_settings.h"
#include "xsp_common.h"

int xsp_default_settings_init();
xspSettings *xsp_default_settings(enum xsp_direction_t direction);
int xsp_set_default_settings(xspSettings *settings, enum xsp_direction_t direction);

#endif
