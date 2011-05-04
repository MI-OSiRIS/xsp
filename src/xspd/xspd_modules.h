#ifndef XSPD_MODULES_H
#define XSPD_MODULES_H

int xspd_modules_init();
int xspd_load_modules();
int xspd_load_module(char *module_name);

typedef struct xspd_module_t {
	void *handle;
	char *filename;
	char *name;
	char *desc;
	char *dependencies;

	int (*init)();
	int (*opt_handler)();
} xspdModule;

xspdModule *xspd_find_module(char *module_name);

#endif
