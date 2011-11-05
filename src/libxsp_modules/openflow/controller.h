#ifndef CONTROLLER_H
#define CONTROLLER_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

int controller_init(int, char **);
void controller_start();
void controller_stop();
void of_add_l3_rule(uint64_t dpid, char *ip_src, char *ip_dst,
		uint32_t src_port, uint32_t dst_port, uint16_t duration);
void of_remove_l3_rule(uint64_t dpid, char *ip_src, char *ip_dst,
		uint32_t src_port, uint32_t dst_port);

#ifdef __cplusplus
}
#endif

#endif
