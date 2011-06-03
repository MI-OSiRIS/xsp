#include <stdlib.h>
#include <string.h>

#include "libxsp_net_path.h"

xspNetPath *xsp_alloc_net_path() {
	xspNetPath *new_path;

        new_path = malloc(sizeof(xspNetPath));
        if (!new_path)
                goto error_exit;
	
        memset(new_path, 0, sizeof(xspNetPath));

        return new_path;

 error_exit:
        return NULL;
}

xspNetPath *xsp_net_path_new(char *type, int action) {
	xspNetPath *new_path = xsp_alloc_net_path();
	
	if (new_path) {
		strncpy(new_path->type, type, XSP_NET_PATH_LEN);
		new_path->action = action;
		new_path->rules = NULL;
		new_path->rule_count = 0;
	}
	
	return new_path;
}

void xsp_net_path_add_rule(xspNetPath *path, xspNetPathRule *rule) {
	if (path->rules) {
		path->rules = (xspNetPathRule**)realloc(path->rules, path->rule_count + 1);
		path->rules[path->rule_count++] = rule;
	}
	else {
		path->rules = (xspNetPathRule**)malloc(sizeof(xspNetPathRule*));
		path->rules[path->rule_count++] = rule;
	}
}
