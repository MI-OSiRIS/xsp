#ifndef XSP_PATHRULE_HANDLER_H
#define XSP_PATHRULE_HANDLER_H

#include "xsp_path.h"

typedef struct xsp_pathrule_handler_t {
	char *name;
	int (*allocate) (const xspNetPathRule *net_rule, const xspSettings *settings, xspPathRule **ret_rule, char **error_msg);
	char *(*get_pathrule_id) (const xspNetPathRule *net_rule, const xspSettings *settings, char **error_msg);
} xspPathRuleHandler;

int xsp_pathrule_handler_init();
xspPathRuleHandler *xsp_get_pathrule_handler(const char *name);
xspPathRuleHandler **xsp_get_pathrule_handlers(int *ret_count);
int xsp_add_pathrule_handler(xspPathRuleHandler *handler);

#endif
