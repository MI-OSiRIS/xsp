#ifndef MONITORING_H
#define MONITORING_H

#include <stdint.h>
#include "xspd_soap_context.h"


int monitoring_notify(xspdSoapContext *mntr, const char *id, const char *src, 
		      const char *dst,const char *src_port_range, const char *dst_port_range,
                      const char *vlan_id, const char *direction, uint64_t start_time, 
		      uint64_t duration, uint64_t bw,const char *bw_class, const char *status);

int monitoring_set_status(xspdSoapContext *mntr, const char *res_id, const char *status);

int monitoring_remove(xspdSoapContext *mntr, const char *res_id);

#endif
