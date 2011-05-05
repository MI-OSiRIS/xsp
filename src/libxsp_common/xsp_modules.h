#ifndef XSP_MODULES_H
#define XSP_MODULES_H

int xsp_modules_init();
int xsp_load_modules();
int xsp_load_module(char *module_name);

typedef struct xsp_module_t {
	void *handle;
	char *filename;
	char *name;
	char *desc;
	char *dependencies;

	int (*init)();
	int (*opt_handler)();
} xspModule;

xspModule *xsp_find_module(char *module_name);

#endif
