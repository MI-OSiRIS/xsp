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
	// LINUX_NET, OPENFLOW, OSCARS, etc.
	uint16_t        type;
	// the operation the rule performs (route, vlan, etc.)
	// prevents some of the guess-work needed by the backend
	uint16_t        rule_op;
	// EID of the NE to configure
	struct xsp_addr rule_eid;

	// all the supported config criteria
	struct xsp_addr src_eid;
	struct xsp_addr dst_eid;
	struct xsp_addr src_mask;
	struct xsp_addr dst_mask;

	uint32_t src_port;
	uint32_t dst_port;

	uint16_t src_port_min;
	uint16_t src_port_max;
	uint16_t dst_port_min;
	uint16_t dst_port_max;
	
	uint16_t  vlan;
	uint8_t  vlan_priority;
	uint8_t  dscp;
	uint8_t  dscp_class;
	uint32_t mpls;
	uint32_t mpls_class;
	uint8_t  l3_proto;
	int16_t  l2_type;

	uint8_t  status;
	uint8_t  direction;
	uint64_t bandwidth;
	uint64_t start_time;
	uint64_t end_time;
	uint64_t duration;

	void     *priv_data;
	uint64_t priv_data_size;
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
