#ifndef XSP_PATH_HANDLER_H
#define XSP_PATH_HANDLER_H

#include "xsp_path.h"

typedef struct xsp_path_handler_t {
	char *name;
	int (*allocate) (const xspSettings *settings, xspPath **path, char **error_msg);
	char *(*get_path_id) (const xspSettings *settings, char **error_msg);
} xspPathHandler;

int xsp_path_handler_init();
int xsp_get_path_handler(const char *name);
int xsp_add_path_handler(xspPathHandler *handler);
int xsp_get_path(const char *type, xspSettings *settings, xspPath **ret_path, char **error_msg);

#endif
