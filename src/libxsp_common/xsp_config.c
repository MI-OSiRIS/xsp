#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libconfig.h"

#include "xsp_settings.h"
#include "xsp_config.h"
#include "xsp_common.h"

int xsp_config_read(const char *filename, const char *cgroup) {
	config_t root;
	const config_setting_t *group, *def, *connections;
	int i, n, j;
	xspSettings *settings;

	config_init(&root);

	if (config_load_file(&root, filename) == 0) {
		fprintf(stderr, "Couldn't load settings file: %s\n", filename);
		goto error_exit;
	}

	group = config_setting_remove_child(config_root_setting(&root), cgroup);
	if (group && config_setting_type(group) == CONFIG_TYPE_GROUP) {
		settings = xsp_settings_alloc();
		if (settings) {
			settings->root.root = group;

			xsp_set_main_settings(settings);
		}
	}

	connections = config_setting_remove_child(config_root_setting(&root), "connections");
	if (connections && config_setting_type(connections) == CONFIG_TYPE_GROUP) {

		for(j = 0; j < 3; j++) {
			char *section = NULL;
			enum xsp_direction_t direction;

			if (j == 0) {
				section = "incoming";
				direction = XSP_INCOMING;
			} else if (j == 1) {
				section = "outgoing";
				direction = XSP_OUTGOING;
			} else {
				section = NULL;
				direction = XSP_BOTH;
			}

			if (section) {
				group = config_setting_remove_child(connections, section);
				if (!group) {
					continue;
				}
			} else {
				group = connections;
			}

			// get the default settings if it exists
			def = config_setting_remove_child(group, "default");
			if (def && config_setting_type(def) == CONFIG_TYPE_GROUP) {
				settings = xsp_settings_alloc();
				if (settings) {
					config_init(&(settings->root));
					settings->root.root = def;

					xsp_set_default_settings(settings, direction);
				}
			}

			// iterate through the rest of the user/route policies
			while(config_setting_length(group) > 0) {
				config_setting_t *setting;
				char *name;
				char *desc;
				xspSettings *settings;

				setting = config_setting_remove_index(group, 0);
				name = config_setting_name(setting);

				// skip the default settings since we've already set it
				if (!strcasecmp(name, "default")) {
					config_setting_destroy(setting);
					continue;
				}

				// skip if it's not a settings group
				if (config_setting_type(setting) != CONFIG_TYPE_GROUP) {
					config_setting_destroy(setting);
					continue;
				}

				// grab the route/username
				desc = strchr(name, ':');
				if (!desc) {
					config_setting_destroy(setting);
					continue;
				}

				desc++;

				// skip if it's an invalid settings type
				if (strncmp(name, "route", 5) && strncmp(name, "user", 4)) {
					config_setting_destroy(setting);
					continue;
				}

				settings = xsp_settings_alloc();
				if (!settings) {
					config_setting_destroy(setting);
					continue;
				}

				config_init(&(settings->root));
				settings->root.root = setting;
				
				config_setting_destroy(setting);
			}
		}


	}

	return 0;

error_exit2:
	config_destroy(&root);
error_exit:
	return -1;
}
