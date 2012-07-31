#ifndef XSP_FLOODLIGHT_BASIC_H
#define XSP_FLOODLIGHT_BASIC_H

#include <pthread.h>

typedef struct xsp_fl_config_t {
	char *controller_hp;
} xspFLConfig;

typedef struct xsp_fl_entry_list_t {
	void **entries;
	int n_entries;
} xspFLEntries;

#endif
