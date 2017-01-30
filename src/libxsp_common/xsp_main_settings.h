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
#ifndef XSP_MAIN_SETTINGS_H
#define XSP_MAIN_SETTINGS_H

#include "xsp_settings.h"
#include "xsp_common.h"

int xsp_main_settings_init();
xspSettings *xsp_main_settings();
int xsp_set_main_settings(xspSettings *settings);

int xsp_main_settings_get_section(const char *section, xspSettings **settings);
int xsp_main_settings_get_subsection(const char *section, const char *subsection, xspSettings **settings);
int xsp_main_settings_get_subsubsection(const char *section, const char *subsection, const char *subsubsection, xspSettings **settings);

int xsp_main_settings_get(const char *section, const char *option, char **value);
int xsp_main_settings_get_int(const char *section, const char *option, int *value);
int xsp_main_settings_get_bool(const char *section, const char *option, int *value);
int xsp_main_settings_get_list(const char *section, const char *option, char ***value, int *count);
int xsp_main_settings_get_range(const char *section, const char *option, int *min, int *max);

int xsp_main_settings_get_1(const char *option, char **value);
int xsp_main_settings_get_int_1(const char *option, int *value);
int xsp_main_settings_get_bool_1(const char *option, int *value);
int xsp_main_settings_get_list_1(const char *option, char ***value, int *count);
int xsp_main_settings_get_range_1(const char *option, int *min, int *max);

int xsp_main_settings_set(const char *section, const char *option, char *value);
int xsp_main_settings_set_int(const char *section, const char *option, int value);
int xsp_main_settings_set_bool(const char *section, const char *option, int value);
int xsp_main_settings_set_list(const char *section, const char *option, char * const *value, int count);
int xsp_main_settings_set_range(const char *section, const char *option, int min, int max);

int xsp_main_settings_get_3(const char *section1, const char *section2, const char *option, char **value);
int xsp_main_settings_get_int_3(const char *section1, const char *section2, const char *option, int *value);
int xsp_main_settings_get_bool_3(const char *section1, const char *section2, const char *option, int *value);
int xsp_main_settings_get_list_3(const char *section1, const char *section2, const char *option, char ***value, int *count);
int xsp_main_settings_get_range_3(const char *section1, const char *section2, const char *option, int *min, int *max);

int xsp_main_settings_get_4(const char *section1, const char *section2, const char *section3, const char *option, char **value);
int xsp_main_settings_get_int_4(const char *section1, const char *section2, const char *section3, const char *option, int *value);
int xsp_main_settings_get_bool_4(const char *section1, const char *section2, const char *section3, const char *option, int *value);
int xsp_main_settings_get_list_4(const char *section1, const char *section2, const char *section3, const char *option, char ***value, int *count);
int xsp_main_settings_get_range_4(const char *section1, const char *section2, const char *section3, const char *option, int *min, int *max);

#endif
