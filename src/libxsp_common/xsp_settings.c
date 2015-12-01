#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "xsp_settings.h"
#include "xsp_default_settings.h"
#include "xsp_logger.h"

#include "libconfig.h"
#include "compat.h"

static config_setting_t *xsp_settings_get_option(const xspSettings *settings, int num_fields, va_list ap, int type, int replace);
static int libconfig_merge_groups(config_setting_t *dst, const config_setting_t *src);
static int libconfig_duplicate_group(config_setting_t *dst, config_setting_t *group);
/*
 *This returns a malloced array of strings whose length can be determined
 * by xsp_settings_get_no_section api Please free it accordingly
 */
int xsp_settings_get_section_names(xspSettings *settings, const char *group,
				  char ***list) {
    config_setting_t *group_setting;
    config_setting_t *elements;
    unsigned int     length;
    int              i = 0;

    group_setting =
	config_setting_get_member(config_root_setting(&settings->root), 
				  group);
    if(!group_setting) {
	fprintf(stderr,"%s group label not found in config", group);
	return -1;
    }
    length = config_setting_length(group_setting);
    *list = (char **)malloc(length * sizeof(char *));
    for (i = 0; i < length ; i++) 
    {
	elements = config_setting_get_elem(group_setting, i);
	(*list)[i] = elements->name;
    }
    return 0;
}
int xsp_settings_get_no_section(xspSettings *settings, const char *group,
				int *value) {
    config_setting_t *group_setting;
    group_setting =
	config_setting_get_member(config_root_setting(&settings->root), 
				  group);
    if(!group_setting) {
	fprintf(stderr,"%s group label not found in config", group);
	return -1;
    }
    *value = config_setting_length(group_setting);
    return 0;
}
int __xsp_settings_getval(const xspSettings *settings, char **value, int num_fields, ...) {
	const config_setting_t *setting;
	char data[1024];
	va_list ap;
	int i;

	va_start(ap, num_fields);

	data[0] = 0;
	for(i = 0; i < num_fields; i++) {
		strlcat(data, ".", sizeof(data));
		strlcat(data, va_arg(ap, const char *), sizeof(data));
	}

	va_end(ap);

	setting = config_lookup(&(settings->root), data);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_STRING)
		goto error_exit;

	*value = strdup(config_setting_get_string(setting));

	return 0;

error_exit:
	return -1;
}

int __xsp_settings_getval_int(const xspSettings *settings, int *value, int num_fields, ...) {
	const config_setting_t *setting;
	char data[1024];
	va_list ap;
	int i;

	va_start(ap, num_fields);

	data[0] = 0;
	for(i = 0; i < num_fields; i++) {
		strlcat(data, ".", sizeof(data));
		strlcat(data, va_arg(ap, const char *), sizeof(data));
	}

	va_end(ap);

	setting = config_lookup(&(settings->root), data);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_INT)
		goto error_exit;

	*value = config_setting_get_int(setting);

	return 0;

error_exit:
	return -1;
}

int __xsp_settings_getval_bool(const xspSettings *settings, int *value, int num_fields, ...) {
	const config_setting_t *setting;
	char data[1024];
	va_list ap;
	int i;

	va_start(ap, num_fields);

	data[0] = 0;
	for(i = 0; i < num_fields; i++) {
		strlcat(data, ".", sizeof(data));
		strlcat(data, va_arg(ap, const char *), sizeof(data));
	}

	va_end(ap);

	setting = config_lookup(&(settings->root), data);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_BOOL)
		goto error_exit;

	*value = config_setting_get_bool(setting);

	return 0;

error_exit:
	return -1;
}

int __xsp_settings_getval_list(const xspSettings *settings, char ***value, int *count, int num_fields, ...) {
	const config_setting_t *setting;
	int i, n;
	char **retval;
	char data[1024];
	va_list ap;

	va_start(ap, num_fields);

	data[0] = 0;
	for(i = 0; i < num_fields; i++) {
		strlcat(data, ".", sizeof(data));
		strlcat(data, va_arg(ap, const char *), sizeof(data));
	}

	va_end(ap);

	setting = config_lookup(&(settings->root), data);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_ARRAY)
		goto error_exit;

	n = config_setting_length(setting);
	if (n == 0)
		goto error_exit;

	retval = malloc(sizeof(char *) * n);
	if (!retval)
		goto error_exit;

	bzero(retval, sizeof(char *) * n);

	for(i = 0; i < n; i++) {
		const char *val;
		val = config_setting_get_string_elem(setting, i);
		if (!val)
			goto error_exit2;

		retval[i] = strdup(val);
		if (!retval[i])
			goto error_exit2;
	}

	*value = retval;
	*count = n;

	return 0;

error_exit2:
	for(i = 0; i < n; i++) {
		if (retval[i] != NULL) {
			free(retval[i]);
		}
	}

	free(retval);
error_exit:
	return -1;

}

int __xsp_settings_getval_group(const xspSettings *settings, xspSettings **ret_settings, int num_fields, ...) {
	config_setting_t *setting;
	int i, n;
	char **retval;
	char data[1024];
	va_list ap;

	va_start(ap, num_fields);

	data[0] = 0;
	for(i = 0; i < num_fields; i++) {
		strlcat(data, ".", sizeof(data));
		strlcat(data, va_arg(ap, const char *), sizeof(data));
	}

	va_end(ap);

	setting = config_lookup(&(settings->root), data);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_GROUP)
		goto error_exit;
	
	*ret_settings = xsp_settings_alloc();
	if (!*ret_settings) {
		goto error_exit;
	}
	
	libconfig_duplicate_group(config_root_setting(&((*ret_settings)->root)), setting);

	return 0;

error_exit:
	return -1;
}

int __xsp_settings_setval(xspSettings *settings, const char *value, int num_fields, ...) {
	config_setting_t *setting;
	va_list ap;

	va_start(ap, num_fields);

	setting = xsp_settings_get_option(settings, num_fields, ap, CONFIG_TYPE_STRING, 0);
	if (!setting) {
		fprintf(stderr, "Couldn't create option\n");
		goto error_exit;
	}

	if (config_setting_set_string(setting, value) != CONFIG_TRUE) {
		fprintf(stderr, "Couldn't set value\n");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

int __xsp_settings_setval_int(xspSettings *settings, int value, int num_fields, ...) {
	config_setting_t *setting;
	va_list ap;

	va_start(ap, num_fields);

	setting = xsp_settings_get_option(settings, num_fields, ap, CONFIG_TYPE_INT, 0);
	if (!setting)
		goto error_exit;

	if (config_setting_set_int(setting, value) != CONFIG_TRUE)
		goto error_exit;

	return 0;

error_exit:
	return -1;
}

int __xsp_settings_setval_bool(xspSettings *settings, int value, int num_fields, ...) {
	config_setting_t *setting;
	va_list ap;

	va_start(ap, num_fields);

	setting = xsp_settings_get_option(settings, num_fields, ap, CONFIG_TYPE_BOOL, 0);
	if (!setting)
		goto error_exit;

	if (config_setting_set_bool(setting, value) != CONFIG_TRUE)
		goto error_exit;

	return 0;

error_exit:
	return -1;
}

int __xsp_settings_setval_list(xspSettings *settings, char * const *values, int count, int num_fields, ...) {
	config_setting_t *setting;
	config_setting_t *group;
	int i;
	va_list ap;

	va_start(ap, num_fields);

	group = xsp_settings_get_option(settings, num_fields, ap, CONFIG_TYPE_ARRAY, 0);
	if (!group)
		goto error_exit;

	for(i = 0; i < count; i++) {
		setting = config_setting_add(group, NULL, CONFIG_TYPE_STRING);
		if (!setting)
			goto error_exit;

		config_setting_set_string(setting, values[i]);
	}

	return 0;

error_exit:
	return -1;
}

static config_setting_t *xsp_settings_get_option(const xspSettings *settings, int num_fields, va_list ap, int type, int replace) {
	config_setting_t *group;
	config_setting_t *setting;
	const char *option;
	int i;

	group = config_root_setting(&(settings->root));

	for(i = 0; i < num_fields - 1; i++) {
		config_setting_t *next_group;
		const char *field = va_arg(ap, const char *);

		next_group = config_setting_get_member(group, field);
		if (!next_group) {
			next_group = config_setting_add(group, field, CONFIG_TYPE_GROUP);
			if (!next_group) {
				fprintf(stderr, "Couldn't add section: \"%s\"\n", field);
				goto error_exit;
			}
		} else if (config_setting_type(group) != CONFIG_TYPE_GROUP) {
			fprintf(stderr, "Field \"%s\" exists, but isn't group\n", field);
			goto error_exit;
		}

		group = next_group;
	}

	option = va_arg(ap, const char *);

	va_end(ap);

	setting = config_setting_get_member(group, option);

	if (setting && replace) {
		config_setting_remove(group, option);
		setting = NULL;
	}

	if (!setting) {
		setting = config_setting_add(group, option, type);
		if (!setting) {
			fprintf(stderr, "Couldn't add option \"%s\"\n", option);
			goto error_exit;
		}
	}

	return setting;

error_exit:
	return NULL;
}

xspSettings *xsp_settings_alloc() {
	xspSettings *settings;

	settings = malloc(sizeof(xspSettings));
	if (!settings)
		goto error_exit;

	config_init(&(settings->root));

	return settings;

error_exit:
	return NULL;
}

void xsp_settings_free(xspSettings *settings) {
	config_destroy(&(settings->root));
	free(settings);
}

xspSettings *xsp_settings_merge(const xspSettings *settings1, const xspSettings *settings2) {
	xspSettings *ret_settings;

	ret_settings = xsp_settings_duplicate(settings1);
	if (!ret_settings)
		goto error_exit;

	if (settings2) {
		libconfig_merge_groups(config_root_setting(&(ret_settings->root)), config_root_setting(&(settings2->root)));
	}

	return ret_settings;

error_exit:
	return NULL;
}

xspSettings *xsp_settings_duplicate(const xspSettings *settings) {
	xspSettings *ret_settings;

	ret_settings = xsp_settings_alloc();
	if (!ret_settings)
		goto error_exit;

	libconfig_duplicate_group(config_root_setting(&(ret_settings->root)), config_root_setting(&(settings->root)));

	return ret_settings;

error_exit:
	return NULL;
}

static int libconfig_duplicate_group(config_setting_t *dst, config_setting_t *src) {
	int i;

	for(i = 0; i < config_setting_length(src); i++) {
		config_setting_t *curr, *new;

		curr = config_setting_get_elem(src, i);
		new = config_setting_add(dst, config_setting_name(curr), config_setting_type(curr));

		if (config_setting_type(curr) == CONFIG_TYPE_GROUP || config_setting_type(curr) == CONFIG_TYPE_ARRAY) {
			libconfig_duplicate_group(new, curr);
		} else if (config_setting_type(curr) == CONFIG_TYPE_LIST) {
			// need to handle LIST case
		} else if (config_setting_type(curr) == CONFIG_TYPE_STRING) {
			config_setting_set_string(new, config_setting_get_string(curr));
		} else if (config_setting_type(curr) == CONFIG_TYPE_INT) {
			config_setting_set_int(new, config_setting_get_int(curr));
		} else if (config_setting_type(curr) == CONFIG_TYPE_FLOAT) {
			config_setting_set_float(new, config_setting_get_float(curr));
		} else if (config_setting_type(curr) == CONFIG_TYPE_BOOL) {
			config_setting_set_bool(new, config_setting_get_bool(curr));
		}
	}

	return 0;
}

static int libconfig_merge_groups(config_setting_t *dst, const config_setting_t *src) {
	int i;

	for(i = 0; i < config_setting_length(src); i++) {
		config_setting_t *curr, *new;

		curr = config_setting_get_elem(src, i);
		new = config_setting_get_member(dst, config_setting_name(curr));

		// we just end up adding onto the end of the array if it exists so get rid of it
		if (new && config_setting_type(new) == CONFIG_TYPE_ARRAY) {
			config_setting_remove(dst, config_setting_name(curr));
			new = NULL;
		}

		if (!new) {
			new = config_setting_add(dst, config_setting_name(curr), config_setting_type(curr));
		}

		if (config_setting_type(curr) == CONFIG_TYPE_GROUP || config_setting_type(curr) == CONFIG_TYPE_ARRAY) {
			libconfig_merge_groups(new, curr);
		} else if (config_setting_type(curr) == CONFIG_TYPE_LIST) {
			// need to handle LIST case
		} else if (config_setting_type(curr) == CONFIG_TYPE_STRING) {
			config_setting_set_string(new, config_setting_get_string(curr));
		} else if (config_setting_type(curr) == CONFIG_TYPE_INT) {
			config_setting_set_int(new, config_setting_get_int(curr));
		} else if (config_setting_type(curr) == CONFIG_TYPE_FLOAT) {
			config_setting_set_float(new, config_setting_get_float(curr));
		} else if (config_setting_type(curr) == CONFIG_TYPE_BOOL) {
			config_setting_set_bool(new, config_setting_get_bool(curr));
		}
	}

	return 0;
}

void xsp_settings_print(const xspSettings *settings) {
	config_write(&(settings->root), stdout);
}

void xsp_settings_write(const xspSettings *settings, const char *filename) {
	config_write_file(&(settings->root), filename);
}

int xsp_settings_get(const xspSettings *settings, const char *setting, char **value) {
	return __xsp_settings_getval(settings, value, 1, setting);
}

int xsp_settings_get_int(const xspSettings *settings, const char *setting, int *value) {
	return __xsp_settings_getval_int(settings, value, 1, setting);
}

int xsp_settings_get_bool(const xspSettings *settings, const char *setting, int *value) {
	return __xsp_settings_getval_bool(settings, value, 1, setting);
}

int xsp_settings_get_list(const xspSettings *settings, const char *setting, char ***value, int *count) {
	return __xsp_settings_getval_list(settings, value, count, 1, setting);
}

int xsp_settings_get_group(const xspSettings *settings, const char *setting, xspSettings **value) {
	return __xsp_settings_getval_group(settings, value, 1, setting);
}

int xsp_settings_set(xspSettings *settings, const char *setting, const char *value) {
	return __xsp_settings_setval(settings, value, 1, setting);
}

int xsp_settings_set_int(xspSettings *settings, const char *setting, int value) {
	return __xsp_settings_setval_int(settings, value, 1, setting);
}

int xsp_settings_set_bool(xspSettings *settings, const char *setting, int value) {
	return __xsp_settings_setval_bool(settings, value, 1, setting);
}

int xsp_settings_set_list(xspSettings *settings, const char *setting, char * const *values, int num_values) {
	return __xsp_settings_setval_list(settings, values, num_values, 1, setting);
}

int xsp_settings_get_2(const xspSettings *settings, const char *section, const char *setting, char **value) {
	return __xsp_settings_getval(settings, value, 2, section, setting);
}

int xsp_settings_get_int_2(const xspSettings *settings, const char *section, const char *setting, int *value) {
	return __xsp_settings_getval_int(settings, value, 2, section, setting);
}

int xsp_settings_get_bool_2(const xspSettings *settings, const char *section, const char *setting, int *value) {
	return __xsp_settings_getval_bool(settings, value, 2, section, setting);
}

int xsp_settings_get_list_2(const xspSettings *settings, const char *section, const char *setting, char ***values, int *count) {
	return __xsp_settings_getval_list(settings, values, count, 2, section, setting);
}

int xsp_settings_get_group_2(const xspSettings *settings, const char *section, const char *setting, xspSettings **value) {
	return __xsp_settings_getval_group(settings, value, 2, section, setting);
}

int xsp_settings_set_2(xspSettings *settings, const char *section, const char *setting, const char *value) {
	return __xsp_settings_setval(settings, value, 2, section, setting);
}

int xsp_settings_set_int_2(xspSettings *settings, const char *section, const char *setting, int value) {
	return __xsp_settings_setval_int(settings, value, 2, section, setting);
}

int xsp_settings_set_bool_2(xspSettings *settings, const char *section, const char *setting, int value) {
	return __xsp_settings_setval_bool(settings, value, 2, section, setting);
}

int xsp_settings_set_list_2(xspSettings *settings, const char *section, const char *setting, char * const *values, int num_values) {
	return __xsp_settings_setval_list(settings, values, num_values, 2, section, setting);
}

// 3 sections deep
int xsp_settings_get_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, char **value) {
	return __xsp_settings_getval(settings, value, 3, section1, section2, setting);
}

int xsp_settings_get_int_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, int *value) {
	return __xsp_settings_getval_int(settings, value, 3, section1, section2, setting);
}

int xsp_settings_get_bool_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, int *value) {
	return __xsp_settings_getval_bool(settings, value, 3, section1, section2, setting);
}

int xsp_settings_get_list_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, char ***values, int *count) {
	return __xsp_settings_getval_list(settings, values, count, 3, section1, section2, setting);
}

int xsp_settings_get_group_3(const xspSettings *settings, const char *section1, const char *section2, const char *setting, xspSettings **value) {
	return __xsp_settings_getval_group(settings, value, 3, section1, section2, setting);
}

int xsp_settings_set_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, const char *value) {
	return __xsp_settings_setval(settings, value, 3, section1, section2, setting);
}

int xsp_settings_set_int_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, int value) {
	return __xsp_settings_setval_int(settings, value, 3, section1, section2, setting);
}

int xsp_settings_set_bool_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, int value) {
	return __xsp_settings_setval_bool(settings, value, 3, section1, section2, setting);
}

int xsp_settings_set_list_3(xspSettings *settings, const char *section1, const char *section2, const char *setting, char * const *values, int num_values) {
	return __xsp_settings_setval_list(settings, values, num_values, 3, section1, section2, setting);
}

// 4 sections deep
int xsp_settings_get_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char **value) {
	return __xsp_settings_getval(settings, value, 4, section1, section2, section3, setting);
}

int xsp_settings_get_int_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *value) {
	return __xsp_settings_getval_int(settings, value, 4, section1, section2, section3, setting);
}

int xsp_settings_get_bool_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int *value) {
	return __xsp_settings_getval_bool(settings, value, 4, section1, section2, section3, setting);
}

int xsp_settings_get_list_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char ***values, int *count) {
	return __xsp_settings_getval_list(settings, values, count, 4, section1, section2, section3, setting);
}

int xsp_settings_get_group_4(const xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, xspSettings **value) {
	return __xsp_settings_getval_group(settings, value, 4, section1, section2, section3, setting);
}

int xsp_settings_set_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, const char *value) {
	return __xsp_settings_setval(settings, value, 4, section1, section2, section3, setting);
}

int xsp_settings_set_int_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int value) {
	return __xsp_settings_setval_int(settings, value, 4, section1, section2, section3, setting);
}

int xsp_settings_set_bool_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, int value) {
	return __xsp_settings_setval_bool(settings, value, 4, section1, section2, section3, setting);
}

int xsp_settings_set_list_4(xspSettings *settings, const char *section1, const char *section2, const char *section3, const char *setting, char * const *values, int num_values) {
	return __xsp_settings_setval_list(settings, values, num_values, 4, section1, section2, section3, setting);
}
