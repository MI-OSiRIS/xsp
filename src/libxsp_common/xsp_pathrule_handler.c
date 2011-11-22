#include <string.h>

#include "xsp_pathrule_handler.h"

static xspPathRuleHandler *pathrule_handlers[255];

int xsp_pathrule_handler_init() {
	bzero(pathrule_handlers, sizeof(xspPathRuleHandler *) * 255);
	return 0;
}

xspPathRuleHandler *xsp_get_pathrule_handler(const char *name) {
	uint8_t i;

	for(i = 0;  i < 255; i++) {
		if (pathrule_handlers[i] != NULL) {
			if (strcasecmp(pathrule_handlers[i]->name, name) == 0)
				return pathrule_handlers[i];
		}
	}

	return NULL;
}

xspPathRuleHandler **xsp_get_pathrule_handlers(int *ret_count) {
	uint8_t i;
	uint8_t count = 0;
	xspPathRuleHandler **ret_handlers = NULL;
	
	for(i = 0; pathrule_handlers[i] != NULL; i++)
		count++;
	
	ret_handlers = malloc(count * sizeof(xspPathRuleHandler*));

	for(i = 0;  i < (pathrule_handlers[i] != NULL); i++)
		ret_handlers[i] = pathrule_handlers[i];
	
	*ret_count = count;

	return ret_handlers;
}

int xsp_add_pathrule_handler(xspPathRuleHandler *handler) {
	uint8_t i;

	for(i = 0;  i < 255; i++) {
		if (pathrule_handlers[i] != NULL) {
			if (strcasecmp(pathrule_handlers[i]->name, handler->name) == 0)
				break;
		} else {
			break;
		}
	}

	if (i == 255) {
		return -1;
	}

	pathrule_handlers[i] = handler;

	return 0;
}

