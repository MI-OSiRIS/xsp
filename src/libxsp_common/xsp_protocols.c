// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "xsp_protocols.h"
#include "xsp_config.h"

#include "compat.h"

static xspProtocolHandler *protocols[255];
static char *protocol_list;

int xsp_protocol_init() {

	bzero(protocols, sizeof(xspProtocolHandler *) * 255);

	return 0;
}

char **xsp_get_protocol_list(int *num_protocols) {
	char **ret_list;
	int num;
	int i, n;
       
	ret_list = NULL;
	num = 0;
	for(i = 0; i < 255; i++) {
		if (protocols[i] != NULL) {
			strlist_add(protocols[i]->name, &ret_list, &num);
		}
	}

	*num_protocols = num;

	return ret_list;
}

int xsp_get_protocol(const char *name) {
	uint8_t i;

	for(i = 0;  i < 255; i++) {
		if (protocols[i] != NULL) {
			if (strcasecmp(protocols[i]->name, name) == 0)
				return i;
		}
	}

	return -1;
}

int xsp_add_protocol_handler(xspProtocolHandler *handler) {
	uint8_t i;

	for(i = 0;  i < 255; i++) {
		if (protocols[i] != NULL) {
			if (strcasecmp(protocols[i]->name, handler->name) == 0)
				break;
		} else {
			break;
		}
	}

	if (i == 255) {
		return -1;
	}

	if (protocol_list != NULL) {
		char *new_protocol_list;

		if (asprintf(&new_protocol_list, "%s %s", protocol_list, handler->name) == -1) {
			return -1;
		}

		free(protocol_list);
		protocol_list = new_protocol_list;
	} else {
		if (asprintf(&protocol_list, "%s", handler->name) == -1) {
			protocol_list = NULL;
			return -1;
		}
	}

	protocols[i] = handler;

	return 0;
}

xspConn *xsp_protocol_connect_host(const char *hostname, const char *protocol, xspSettings *settings) {
	int num;

	if (!protocol)
		goto error_exit;

	num = xsp_get_protocol(protocol);
	if (num < 0) {
		goto error_exit;
	}

	return protocols[num]->connect(hostname, settings);

error_exit:
	return NULL;
}

xspListener *xsp_protocol_setup_listener(const char *listener_id, const char *protocol, xspSettings *settings, int one_shot, listener_cb cb, void *arg) {
	int num;
	if (!protocol)
		goto error_exit;
	num = xsp_get_protocol(protocol);
		
	if (num < 0) {
		goto error_exit;
	}
	return protocols[num]->setup_listener(listener_id, settings, one_shot, cb, arg);

error_exit:
	return NULL;
}

const xspSettingDesc *xsp_protocol_get_available_settings (const char *protocol, int *desc_count) {
	int num;

	if (!protocol)
		goto error_exit;

	num = xsp_get_protocol(protocol);
	if (num < 0) {
		goto error_exit;
	}

	return protocols[num]->get_settings(desc_count);

error_exit:
	return NULL;
}
