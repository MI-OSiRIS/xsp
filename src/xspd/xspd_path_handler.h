#ifndef XSPD_PATH_HANDLER_H
#define XSPD_PATH_HANDLER_H

#include "xspd_path.h"

typedef struct xspd_path_handler_t {
	char *name;
	int (*allocate) (const xspdSettings *settings, xspdPath **path, char **error_msg);
	char *(*get_path_id) (const xspdSettings *settings, char **error_msg);
} xspdPathHandler;

int xspd_path_handler_init();
int xspd_get_path_handler(const char *name);
int xspd_add_path_handler(xspdPathHandler *handler);
int xspd_get_path(const char *type, xspdSettings *settings, xspdPath **ret_path, char **error_msg);

#endif
