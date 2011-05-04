#ifndef XSPD_DEFAULT_SETTINGS_H
#define XSPD_DEFAULT_SETTINGS_H

#include "xspd_settings.h"
#include "xspd_common.h"

int xspd_default_settings_init();
xspdSettings *xspd_default_settings(enum xspd_direction_t direction);
int xspd_set_default_settings(xspdSettings *settings, enum xspd_direction_t direction);

#endif
