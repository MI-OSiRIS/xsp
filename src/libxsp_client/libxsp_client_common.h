#ifndef LIBXSP_CLIENT_COMMON_H
#define LIBXSP_CLIENT_COMMON_H


typedef struct libxsp_net_path_rule_crit {
	char *src;
	char *dst;
	uint64_t src_mask;
	uint32_t src_port;
	uint32_t dst_port;

	// add remaining fields exported to clients                                                                              
} libxspNetPathRuleCrit;


#endif
