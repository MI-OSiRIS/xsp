#ifndef XSP_OSCARS_BASIC_H
#define XSP_OSCARS_BASIC_H

#include <pthread.h>

#include "xsp_soap_context.h"

#define OSCARS_DOWN		    0x00
#define OSCARS_UP		    0x01
#define OSCARS_STARTING		    0x02

#define PATH_SHARED		    0x00
#define PATH_PRIVATE	            0x01

typedef struct xsp_oscars_path_t {
	xspSoapContext osc;

	int status;

	char *src;
	int src_tagged;

	char *dst;
	int dst_tagged;

	char *reservation_id;

	int duration;

	char *src_vlan_id;
	char *dst_vlan_id;

	int clock_offset;

	int sleep_time;

	int teardown_timeout;

	int reservation_timeout;

	int intercircuit_pause_time;

	uint16_t bandwidth, bandwidth_used;

	time_t shutdown_time;

	int type;
	
	int bw;

	pthread_cond_t setup_cond;
} xspOSCARSPath;

#endif
