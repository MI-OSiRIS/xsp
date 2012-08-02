#ifndef XSP_UNIS_H
#define XSP_UNIS_H

#define XSP_UNIS_REFRESH_TO   60
#define XSP_UNIS_REG_INTERVAL 720

typedef struct xsp_unis_config_t {
	char *endpoint;
	int do_register;
	int registration_interval;
	int refresh_timer;
} xspUNISConfig;

#endif
