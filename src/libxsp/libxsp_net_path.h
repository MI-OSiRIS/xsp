#ifndef LIBXSP_NET_PATH_H
#define LIBXSP_NET_PATH_H

#include "xsp-proto.h"

enum xsp_sess_net_path_actions_t {
	XSP_NET_PATH_CREATE = 0,
	XSP_NET_PATH_DELETE,
	XSP_NET_PATH_MODIFY,
	XSP_NET_PATH_QUERY
};

typedef struct xsp_sess_net_path_rule_t {
	struct xsp_addr src_eid;
	struct xsp_addr src_mask;
	struct xsp_addr dst_eid;
	struct xsp_addr dst_mask;

	int src_port_min;
	int src_port_max;
	int dst_port_min;
	int dst_port_max;
	
	int direction;
	uint64_t bandwidth;
	int status;
} xspNetPathRule;

typedef struct xsp_sess_net_path_t {
	char type[XSP_NET_PATH_LEN+1];
	int action;
	
	xspNetPathRule **rules;
	int rule_count;
} xspNetPath;
	
xspNetPath *xsp_alloc_net_path();
xspNetPath *xsp_net_path_new(char *type, int action);
void xsp_net_path_add_rule(xspNetPath *path, xspNetPathRule *rule);

#endif
