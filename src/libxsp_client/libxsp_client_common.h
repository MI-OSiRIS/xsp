#ifndef LIBXSP_CLIENT_COMMON_H
#define LIBXSP_CLIENT_COMMON_H

typedef struct libxsp_net_path_rule_crit {
	char *iface;
	char *src;
	char *dst;
	char *src_mask;
	char *dst_mask;
	uint16_t vlan;
	uint32_t src_port;
	uint32_t dst_port;

	// add remaining fields exported to clients                                                                              
} libxspNetPathRuleCrit;


#endif
