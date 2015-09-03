#ifndef XSP_OESS_BASIC_H
#define XSP_OESS_BASIC_H

#include <pthread.h>

enum {
	OESS_DATA = 0,
	OESS_MEASUREMENT,
	OESS_MONITORING,
	OESS_PROVISIONING,
	OESS_REMOTE,
};

typedef struct xsp_oess_config_t {
	char *service_ap;
	char *login;
	char *password;
	char *realm;
	char *project;
	void *auth_handler;
} xspOESSConfig;

#endif
