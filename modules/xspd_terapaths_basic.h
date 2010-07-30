#ifndef XSPD_TERAPATHS_BASIC_H
#define XSPD_TERAPATHS_BASIC_H

#include <pthread.h>

#define TPS_DOWN            0x00
#define TPS_UP		    0x01
#define TPS_STARTING	    0x02

#define PATH_PRIVATE        0x00
#define PATH_SHARED         0x01

typedef struct xspd_terapaths_path_t {
	xspdSoapContext tsc;
	xspdSoapContext msc;

	char *src;
	char *dst;

	char *src_ports;
	char *dst_ports;

	char *direction;
	char *bw_class;

	uint64_t bw;
	uint64_t bw_used;
	uint64_t start_time;
	uint64_t duration;

	char *reservation_id;
	char *related_res_ids;
	char *vlan_tag;

	int sleep_time;

	int teardown_timeout;

	int start_offset;
	
	int type;
	int status;
	pthread_cond_t setup_cond;
} xspdTERAPATHSPath;

#endif
