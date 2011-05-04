#ifndef TERAPATHS_H
#define TERAPATHS_H

#include <stdint.h>
#include "xspd_soap_context.h"

typedef struct terapaths_bandwidth_t {
  int size;
  char **class;
  uint64_t *bw;
} tpsBandwidth;


typedef struct terapaths_bandwidths_t {
  int size;
  tpsBandwidth **bws;
} tpsBandwidths;

typedef struct terapaths_path_t {
  int size;
  char **path;
} tpsPath;

int terapaths_reserve(xspdSoapContext *tsc, const char *src, const char *dst,
		      const char *src_ports, const char *dst_ports,
		      const char *direction, const char *bw_class, uint64_t bw,
		      uint64_t start_time, uint64_t duration, char **res_id);

int terapaths_commit(xspdSoapContext *tsc, const char *res_id);

int terapaths_cancel(xspdSoapContext *tsc, const char *res_id);

int terapaths_get_bandwidths(xspdSoapContext *tsc, const char *src, const char *dst, tpsBandwidths *res_result);

int terapaths_get_path(xspdSoapContext *tsc, const char *src, const char *dst, tpsPath *res_result);

int terapaths_get_related_ids(xspdSoapContext *tsc, const char *res_id, char **rel_ids);

#endif
