#ifndef XSPD_SETTINGS_H
#define XSPD_SETTINGS_H

#include "libconfig.h"

enum xspd_setting_types { XSPD_SETTING_STRING, XSPD_SETTING_BOOL, XSPD_SETTING_INT, XSPD_SETTING_LIST };

typedef struct xspd_settings_t {
	config_t root;
} xspdSettings;

typedef struct xspd_setting_desc_t {
	char *name;
	enum xspd_setting_types type;
} xspdSettingDesc;

inline int xspd_settings_get(const xspdSettings *settings, const char *setting, char **value);
inline int xspd_settings_get_int(const xspdSettings *settings, const char *setting, int *value);
inline int xspd_settings_get_bool(const xspdSettings *settings, const char *setting, int *value);
inline int xspd_settings_get_list(const xspdSettings *settings, const char *setting, char ***value, int *count);
inline int xspd_settings_get_range(const xspdSettings *settings, const char *setting, int *min, int *max);
inline int xspd_settings_get_group(const xspdSettings *settings, const char *setting, xspdSettings **value);

inline int xspd_settings_set(xspdSettings *settings, const char *setting, const char *value);
inline int xspd_settings_set_int(xspdSettings *settings, const char *setting, int value);
inline int xspd_settings_set_bool(xspdSettings *settings, const char *setting, int value);
inline int xspd_settings_set_list(xspdSettings *settings, const char *setting, char * const *values, int num_values);
inline int xspd_settings_set_range(xspdSettings *settings, const char *setting, int min, int max);

inline int xspd_settings_get_2(const xspdSettings *settings, const char *section, const char *setting, char **value);
inline int xspd_settings_get_int_2(const xspdSettings *settings, const char *section, const char *setting, int *value);
inline int xspd_settings_get_bool_2(const xspdSettings *settings, const char *section, const char *setting, int *value);
inline int xspd_settings_get_list_2(const xspdSettings *settings, const char *section, const char *setting, char ***value, int *count);
inline int xspd_settings_get_range_2(const xspdSettings *settings, const char *section, const char *setting, int *min, int *max);
inline int xspd_settings_get_group_2(const xspdSettings *settings, const char *section, const char *setting, xspdSettings **value);

inline int xspd_settings_set_2(xspdSettings *settings, const char *section, const char *setting, const char *value);
inline int xspd_settings_set_int_2(xspdSettings *settings, const char *section, const char *setting, int value);
inline int xspd_settings_set_bool_2(xspdSettings *settings, const char *section, const char *setting, int value);
inline int xspd_settings_set_list_2(xspdSettings *settings, const char *section, const char *setting, char * const *values, int num_values);
inline int xspd_settings_set_range_2(xspdSettings *settings, const char *section, const char *setting, int min, int max);

inline int xspd_settings_get_3(const xspdSettings *settings, const char *section1, const char *section2, const char *setting, char **value);
inline int xspd_settings_get_int_3(const xspdSettings *settings, const char *section1, const char *section2, const char *setting, int *value);
inline int xspd_settings_get_bool_3(const xspdSettings *settings, const char *section1, const char *section2, const char *setting, int *value);
inline int xspd_settings_get_list_3(const xspdSettings *settings, const char *section1, const char *section2, const char *setting, char ***value, int *count);
inline int xspd_settings_get_range_3(const xspdSettings *settings, const char *section1, const char *section2, const char *setting, int *min, int *max);
inline int xspd_settings_get_group_3(const xspdSettings *settings, const char *section1, const char *section2, const char *setting, xspdSettings **value);

inline int xspd_settings_set_3(xspdSettings *settings, const char *section1, const char *section2, const char *setting, const char *value);
inline int xspd_settings_set_int_3(xspdSettings *settings, const char *section1, const char *section2, const char *setting, int value);
inline int xspd_settings_set_bool_3(xspdSettings *settings, const char *section1, const char *section2, const char *setting, int value);
inline int xspd_settings_set_list_3(xspdSettings *settings, const char *section1, const char *section2, const char *setting, char * const *values, int num_values);
inline int xspd_settings_set_range_3(xspdSettings *settings, const char *section1, const char *section2, const char *setting, int min, int max);

inline int xspd_settings_get_4(const xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char **value);
inline int xspd_settings_get_int_4(const xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *value);
inline int xspd_settings_get_bool_4(const xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *value);
inline int xspd_settings_get_list_4(const xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char ***value, int *count);
inline int xspd_settings_get_range_4(const xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *min, int *max);
inline int xspd_settings_get_group_4(const xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, xspdSettings **value);

inline int xspd_settings_set_4(xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, const char *value);
inline int xspd_settings_set_int_4(xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int value);
inline int xspd_settings_set_bool_4(xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int value);
inline int xspd_settings_set_list_4(xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char * const *values, int num_values);
inline int xspd_settings_set_range_4(xspdSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int min, int max);

xspdSettings *xspd_settings_alloc();
void xspd_settings_free(xspdSettings *settings);

xspdSettings *xspd_settings_duplicate(const xspdSettings *settings);
xspdSettings *xspd_settings_merge(const xspdSettings *settings1, const xspdSettings *settings2);
void xspd_settings_print(const xspdSettings *settings);
void xspd_settings_write(const xspdSettings *settings, const char *filename);

int xspd_read_settings(const char *filename);

#endif
