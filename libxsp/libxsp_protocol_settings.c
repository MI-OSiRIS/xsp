#include <stdlib.h>
#include <string.h>

#include "libxsp_protocol_settings.h"

#include "libconfig.h"

static config_setting_t *xsp_protocol_settings_get_option(xspProtocolSettings *settings, const char *option, int type);

xspProtocolSettings *xsp_alloc_protocol_settings() {
	xspProtocolSettings *settings;

	settings = malloc(sizeof(xspProtocolSettings));
	if (!settings)
		goto error_exit;

	config_init(&(settings->root));

	return settings;

error_exit:
	return NULL;
}

void xsp_free_protocol_settings(xspProtocolSettings *settings) {
	config_destroy(&(settings->root));
	free(settings);

}

int xsp_protocol_settings_getval(xspProtocolSettings *settings, const char *option, char **value) {
	const config_setting_t *setting;

	setting = config_lookup(&(settings->root), option);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_STRING)
		goto error_exit;

	*value = strdup(config_setting_get_string(setting));

	return 0;

error_exit:
	return -1;

}

int xsp_protocol_settings_getval_int(xspProtocolSettings *settings, const char *option, int *value) {
	const config_setting_t *setting;

	setting = config_lookup(&(settings->root), option);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_INT)
		goto error_exit;

	*value = config_setting_get_int(setting);

	return 0;

error_exit:
	return -1;
}

int xsp_protocol_settings_getval_bool(xspProtocolSettings *settings, const char *option, int *value) {
	const config_setting_t *setting;

	setting = config_lookup(&(settings->root), option);
	if (!setting)
		goto error_exit;

	if (config_setting_type(setting) != CONFIG_TYPE_BOOL)
		goto error_exit;

	*value = config_setting_get_bool(setting);

	return 0;

error_exit:
	return -1;

}

int xsp_protocol_settings_setval(xspProtocolSettings *settings, const char *option, char *value) {
	config_setting_t *setting;

	setting = xsp_protocol_settings_get_option(settings, option, CONFIG_TYPE_STRING);
	if (!setting)
		goto error_exit;

	if (config_setting_set_string(setting, value) != CONFIG_TRUE)
		goto error_exit;

	return 0;

error_exit:
	return -1;
}

int xsp_protocol_settings_setval_int(xspProtocolSettings *settings, const char *option, int value) {
	config_setting_t *setting;

	setting = xsp_protocol_settings_get_option(settings, option, CONFIG_TYPE_INT);
	if (!setting)
		goto error_exit;

	if (config_setting_set_int(setting, value) != CONFIG_TRUE)
		goto error_exit;

	return 0;

error_exit:
	return -1;
}

int xsp_protocol_settings_setval_bool(xspProtocolSettings *settings, const char *option, int value) {
	config_setting_t *setting;

	setting = xsp_protocol_settings_get_option(settings, option, CONFIG_TYPE_BOOL);
	if (!setting)
		goto error_exit;

	if (config_setting_set_bool(setting, value) != CONFIG_TRUE)
		goto error_exit;

	return 0;

error_exit:
	return -1;
}

static config_setting_t *xsp_protocol_settings_get_option(xspProtocolSettings *settings, const char *option, int type) {
	config_setting_t *setting;

	setting = config_setting_get_member(config_root_setting(&(settings->root)), option);
	if (!setting) {
		setting = config_setting_add(config_root_setting(&(settings->root)), option, type);
		if (!setting)
			goto error_exit;
	}

	return setting;

error_exit:
	return NULL;
}
