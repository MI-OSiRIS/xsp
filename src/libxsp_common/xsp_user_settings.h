#ifndef XSP_USER_POLICY_H
#define XSP_USER_POLICY_H

#include "xsp_settings.h"
#include "xsp_common.h"

int xsp_user_settings_init();
xspSettings *xsp_user_settings(const char *user, enum xsp_direction_t direction);
int xsp_set_user_settings(char *user, enum xsp_direction_t direction, xspSettings *settings);

#endif
