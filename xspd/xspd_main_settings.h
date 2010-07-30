#ifndef XSPD_MAIN_SETTINGS_H
#define XSPD_MAIN_SETTINGS_H

#include "xspd_settings.h"
#include "xspd_common.h"

int xspd_main_settings_init();
xspdSettings *xspd_main_settings();
int xspd_set_main_settings(xspdSettings *settings);

int xspd_main_settings_get_section(const char *section, xspdSettings **settings);
int xspd_main_settings_get_subsection(const char *section, const char *subsection, xspdSettings **settings);
int xspd_main_settings_get_subsubsection(const char *section, const char *subsection, const char *subsubsection, xspdSettings **settings);

int xspd_main_settings_get(const char *section, const char *option, char **value);
int xspd_main_settings_get_int(const char *section, const char *option, int *value);
int xspd_main_settings_get_bool(const char *section, const char *option, int *value);
int xspd_main_settings_get_list(const char *section, const char *option, char ***value, int *count);
int xspd_main_settings_get_range(const char *section, const char *option, int *min, int *max);

int xspd_main_settings_set(const char *section, const char *option, char *value);
int xspd_main_settings_set_int(const char *section, const char *option, int value);
int xspd_main_settings_set_bool(const char *section, const char *option, int value);
int xspd_main_settings_set_list(const char *section, const char *option, char * const *value, int count);
int xspd_main_settings_set_range(const char *section, const char *option, int min, int max);

int xspd_main_settings_get_3(const char *section1, const char *section2, const char *option, char **value);
int xspd_main_settings_get_int_3(const char *section1, const char *section2, const char *option, int *value);
int xspd_main_settings_get_bool_3(const char *section1, const char *section2, const char *option, int *value);
int xspd_main_settings_get_list_3(const char *section1, const char *section2, const char *option, char ***value, int *count);
int xspd_main_settings_get_range_3(const char *section1, const char *section2, const char *option, int *min, int *max);

int xspd_main_settings_get_4(const char *section1, const char *section2, const char *section3, const char *option, char **value);
int xspd_main_settings_get_int_4(const char *section1, const char *section2, const char *section3, const char *option, int *value);
int xspd_main_settings_get_bool_4(const char *section1, const char *section2, const char *section3, const char *option, int *value);
int xspd_main_settings_get_list_4(const char *section1, const char *section2, const char *section3, const char *option, char ***value, int *count);
int xspd_main_settings_get_range_4(const char *section1, const char *section2, const char *section3, const char *option, int *min, int *max);

#endif
