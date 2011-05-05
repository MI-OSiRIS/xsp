#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "hashtable.h"
#include "xsp_config.h"
#include "xsp_modules.h"
#include "xsp_logger.h"

#include "compat.h"

static char **modules;
static int module_count;

static struct hashtable *table;

struct xsp_modules_config_t {
	char *module_list;
	char *module_dir;
};

struct xsp_modules_config_t xspModulesConfig = {
	.module_list = "tcp",
#ifdef MODULE_DIR
	.module_dir  = MODULE_DIR
#else
	.module_dir  = "."
#endif
};

static int xsp_modules_htable_equal(const void *k1, const void *k2) {
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

static unsigned int xsp_modules_htable_hash(const void *k1) {
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

int xsp_modules_init() {

	table = create_hashtable(7, xsp_modules_htable_hash, xsp_modules_htable_equal);
	if (!table) {
		xsp_err(0, "couldn't allocate hashtable");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

static void xsp_modules_read_config() {
	char *str_val;
	
	if (xsp_main_settings_get("modules", "list", &str_val) == 0) {
		xspModulesConfig.module_list = str_val;
	}
	else {
		xsp_info(5, "no modules list section found");
	}

	if (xsp_main_settings_get("modules", "dir", &str_val) == 0) {
		xspModulesConfig.module_dir = str_val;
	}
}

int xsp_load_module(char *module_name) {
	xspModule *(*module_info_function)();
	int n;
	xspModule *module;
	void *handle;
	char filename[1024];

#ifdef EMBED_UDT
	if (strcmp(module_name, "udt") == 0)
		return;
#endif

	xsp_info(0, "loading: %s", module_name);

	// already loaded
	if (hashtable_search(table, module_name))
		return 0;

	strlcpy(filename, xspModulesConfig.module_dir, sizeof(filename));
	strlcat(filename, "/", sizeof(filename));
	strlcat(filename, module_name, sizeof(filename));
	strlcat(filename, ".so", sizeof(filename));

	handle = dlopen(filename, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		xsp_err(0, "couldn't open module %s: %s", module_name, dlerror());
		goto error_exit;
	}

	module_info_function = dlsym(handle, "module_info");
	if (!module_info_function) {
		xsp_err(0, "module %s has no module registration function", module_name);
		goto error_exit2;
	}

	module = module_info_function();
	if (!module) {
		xsp_err(0, "module registration failed: %s", module_name);
		goto error_exit2;
	}

	module->handle = handle;
	module->name = strdup(module_name);
	module->filename = strdup(filename);

	if (!hashtable_insert(table, strdup(module->name), module)) {
		xsp_err(0, "couldn't insert module information into hashtable");
		goto error_exit2;
	}

	if (module->dependencies != NULL) {
		char **dependencies;
		int dependencies_count;
		int i;

		dependencies = split(module->dependencies, " ", &dependencies_count);

		for(i = 0; i < dependencies_count; i++) {
			if (!xsp_find_module(dependencies[i])) {
				
				if (xsp_load_module(dependencies[i])) {
					int j;
					
					xsp_err(0, "module %s couldn't load %s", module_name, dependencies[i]);
					
					for(j = i; j < dependencies_count; j++)
						free(dependencies[j]);
					free(dependencies);
					
					goto error_exit3;
				}
			}
			free(dependencies[i]);
			dependencies[i] = NULL;
		}

		if (dependencies)
			free(dependencies);
	}

	n = module->init();
	if (n != 0) {
		xsp_err(0, "initialization of module %s failed: %d", module_name, n);
		goto error_exit3;
	}

	xsp_info(0, "loaded: %s", module_name);

	return 0;

error_exit3:
	hashtable_remove(table, module->name);
error_exit2:
	dlclose(handle);
error_exit:
	return -1;
}

int xsp_load_modules() {
	int i;

	xsp_modules_read_config();

	modules = split(xspModulesConfig.module_list, " ", &module_count);
	xsp_info(0,"xsp_load_modules() : module_count : %d",module_count);
	for(i = 0; i < module_count; i++) {
		xsp_load_module(modules[i]);
	}

	return 0;
}

xspModule *xsp_find_module(char *module_name) {
	xspModule *module;
	
	if ((module = (xspModule*) hashtable_search(table, module_name)) != NULL)
		return module;
	
	return NULL;
}
