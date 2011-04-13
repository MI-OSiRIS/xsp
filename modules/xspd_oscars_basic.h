#ifndef XSPD_OSCARS_BASIC_H
#define XSPD_OSCARS_BASIC_H

#include <pthread.h>

#define OSCARS_DOWN		    0x00
#define OSCARS_UP		    0x01
#define OSCARS_STARTING		0x02

#define PATH_SHARED		0x00
#define PATH_PRIVATE	0x01

typedef struct xspd_oscars_path_t {
	xspdSoapContext osc;

	int status;

	char *url;

	char *src;
	int src_tagged;

	char *dst;
	int dst_tagged;

	char *java_binary;
	char *axis_path;
	char *client_dir;

	char *reservation_id;

	int duration;

	int vlan_id;

	int clock_offset;

	int sleep_time;

	int teardown_timeout;

	int intercircuit_pause_time;

	uint16_t bandwidth, bandwidth_used;

	time_t shutdown_time;

	int type;

	pthread_cond_t setup_cond;
} xspdOSCARSPath;

#endif
