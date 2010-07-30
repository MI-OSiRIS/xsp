#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "hashtable.h"
#include "xspd_config.h"
#include "xspd_modules.h"
#include "xspd_logger.h"

#include "compat.h"

static char **modules;
static int module_count;

static struct hashtable *table;

struct xspd_modules_config_t {
	char *module_list;
	char *module_dir;
};

struct xspd_modules_config_t xspdModulesConfig = {
	.module_list = "tcp",
#ifdef MODULE_DIR
	.module_dir  = MODULE_DIR
#else
	.module_dir  = "."
#endif
};

static int xspd_modules_htable_equal(const void *k1, const void *k2) {
	const char *c1 = k1;
	const char *c2 = k2;
	int i;

	i = 0;

	while(*c1 != '\0' && *c1 == *c2 && i < 1024) {
		i++;
	}

	if (i == 1024 || *c1 != *c2)
		return -1;

	return 0;
}

static unsigned int xspd_modules_htable_hash(const void *k1) {
	const char *c = k1;
	unsigned int retval;
	int i;

	retval = 0;
	i = 0;

	while(*c != 0 && i < 1024) {
		retval += *c;
		i++;
		c++;
	}

	return retval;
}

int xspd_modules_init() {

	table = create_hashtable(7, xspd_modules_htable_hash, xspd_modules_htable_equal);
	if (!table) {
		xspd_err(0, "couldn't allocate hashtable");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

static void xspd_modules_read_config() {
	char *str_val;
	
	if (xspd_main_settings_get("modules", "list", &str_val) == 0) {
		xspdModulesConfig.module_list = str_val;
	}

	if (xspd_main_settings_get("modules", "dir", &str_val) == 0) {
		xspdModulesConfig.module_dir = str_val;
	}
}

int xspd_load_module(char *module_name) {
	xspdModule *(*module_info_function)();
	int n;
	xspdModule *module;
	void *handle;
	char filename[1024];

#ifdef EMBED_UDT
	if (strcmp(module_name, "udt") == 0)
		return;
#endif

	xspd_info(0, "loading: %s", module_name);

	// already loaded
	if (hashtable_search(table, module_name))
		return 0;

	strlcpy(filename, xspdModulesConfig.module_dir, sizeof(filename));
	strlcat(filename, "/", sizeof(filename));
	strlcat(filename, module_name, sizeof(filename));
	strlcat(filename, ".so", sizeof(filename));

	handle = dlopen(filename, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		xspd_err(0, "couldn't open module %s: %s", module_name, dlerror());
		goto error_exit;
	}

	module_info_function = dlsym(handle, "module_info");
	if (!module_info_function) {
		xspd_err(0, "module %s has no module registration function", module_name);
		goto error_exit2;
	}

	module = module_info_function();
	if (!module) {
		xspd_err(0, "module registration failed: %s", module_name);
		goto error_exit2;
	}

	module->handle = handle;
	module->name = strdup(module_name);
	module->filename = strdup(filename);

	if (!hashtable_insert(table, strdup(module->name), module)) {
		xspd_err(0, "couldn't insert module information into hashtable");
		goto error_exit2;
	}

	if (module->dependencies != NULL) {
		char **dependencies;
		int dependencies_count;
		int i;

		dependencies = split(module->dependencies, " ", &dependencies_count);

		for(i = 0; i < dependencies_count; i++) {
			if (xspd_load_module(dependencies[i])) {
				int j;

				xspd_err(0, "module %s couldn't load %s", module_name, dependencies[i]);

				for(j = i; j < dependencies_count; j++)
					free(dependencies[j]);
				free(dependencies);

				goto error_exit3;
			}

			free(dependencies[i]);
			dependencies[i] = NULL;
		}

		if (dependencies)
			free(dependencies);
	}

	n = module->init();
	if (n != 0) {
		xspd_err(0, "initialization of module %s failed: %d", module_name, n);
		goto error_exit3;
	}

	xspd_info(0, "loaded: %s", module_name);

	return 0;

error_exit3:
	hashtable_remove(table, module->name);
error_exit2:
	dlclose(handle);
error_exit:
	return -1;
}

int xspd_load_modules() {
	int i;

	xspd_modules_read_config();

	modules = split(xspdModulesConfig.module_list, " ", &module_count);
	xspd_info(0,"xspd_load_modules() : module_count : %d",module_count);
	for(i = 0; i < module_count; i++) {
		xspd_load_module(modules[i]);
	}

	return 0;
}
