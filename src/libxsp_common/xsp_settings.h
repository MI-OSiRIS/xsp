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
#ifndef XSP_SETTINGS_H
#define XSP_SETTINGS_H

#include "libconfig.h"

enum xsp_setting_types { XSP_SETTING_STRING, XSP_SETTING_BOOL, XSP_SETTING_INT, XSP_SETTING_LIST };

typedef struct xsp_settings_t {
  config_t root;
} xspSettings;

typedef struct xsp_setting_desc_t {
  char *name;
  enum xsp_setting_types type;
} xspSettingDesc;
int xsp_settings_get_section_names(xspSettings *settings, const char *group,
                                   char ***list);
int xsp_settings_get_no_section(xspSettings *settings, const char *group,
                                int *value);
int xsp_settings_get(const xspSettings *settings, const char *setting, char **value);
int xsp_settings_get_int(const xspSettings *settings, const char *setting, int *value);
int xsp_settings_get_bool(const xspSettings *settings, const char *setting, int *value);
int xsp_settings_get_list(const xspSettings *settings, const char *setting, char ***value, int *count);
int xsp_settings_get_range(const xspSettings *settings, const char *setting, int *min, int *max);
int xsp_settings_get_group(const xspSettings *settings, const char *setting, xspSettings **value);

int xsp_settings_set(xspSettings *settings, const char *setting, const char *value);
int xsp_settings_set_int(xspSettings *settings, const char *setting, int value);
int xsp_settings_set_bool(xspSettings *settings, const char *setting, int value);
int xsp_settings_set_list(xspSettings *settings, const char *setting, char * const *values, int num_values);
int xsp_settings_set_range(xspSettings *settings, const char *setting, int min, int max);

int xsp_settings_get_2(const xspSettings *settings, const char *section, const char *setting, char **value);
int xsp_settings_get_int_2(const xspSettings *settings, const char *section, const char *setting, int *value);
int xsp_settings_get_bool_2(const xspSettings *settings, const char *section, const char *setting, int *value);
int xsp_settings_get_list_2(const xspSettings *settings, const char *section, const char *setting, char ***value, int *count);
int xsp_settings_get_range_2(const xspSettings *settings, const char *section, const char *setting, int *min, int *max);
int xsp_settings_get_group_2(const xspSettings *settings, const char *section, const char *setting, xspSettings **value);

int xsp_settings_set_2(xspSettings *settings, const char *section, const char *setting, const char *value);
int xsp_settings_set_int_2(xspSettings *settings, const char *section, const char *setting, int value);
int xsp_settings_set_bool_2(xspSettings *settings, const char *section, const char *setting, int value);
int xsp_settings_set_list_2(xspSettings *settings, const char *section, const char *setting, char * const *values, int num_values);
int xsp_settings_set_range_2(xspSettings *settings, const char *section, const char *setting, int min, int max);

int xsp_settings_get_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, char **value);
int xsp_settings_get_int_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, int *value);
int xsp_settings_get_bool_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, int *value);
int xsp_settings_get_list_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, char ***value, int *count);
int xsp_settings_get_range_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, int *min, int *max);
int xsp_settings_get_group_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, xspSettings **value);

int xsp_settings_set_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, const char *value);
int xsp_settings_set_int_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, int value);
int xsp_settings_set_bool_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, int value);
int xsp_settings_set_list_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, char * const *values, int num_values);
int xsp_settings_set_range_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, int min, int max);

int xsp_settings_get_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char **value);
int xsp_settings_get_int_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *value);
int xsp_settings_get_bool_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *value);
int xsp_settings_get_list_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char ***value, int *count);
int xsp_settings_get_range_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *min, int *max);
int xsp_settings_get_group_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, xspSettings **value);

int xsp_settings_set_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, const char *value);
int xsp_settings_set_int_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int value);
int xsp_settings_set_bool_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int value);
int xsp_settings_set_list_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char * const *values, int num_values);
int xsp_settings_set_range_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int min, int max);

xspSettings *xsp_settings_alloc();
void xsp_settings_free(xspSettings *settings);

xspSettings *xsp_settings_duplicate(const xspSettings *settings);
xspSettings *xsp_settings_merge(const xspSettings *settings1, const xspSettings *settings2);
void xsp_settings_print(const xspSettings *settings);
void xsp_settings_write(const xspSettings *settings, const char *filename);

int xsp_read_settings(const char *filename);

#endif
