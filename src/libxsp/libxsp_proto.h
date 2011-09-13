#ifndef LIBXSP_PROTOCOL_H
#define LIBXSP_PROTOCOL_H

#include "libxsp.h"
#include "libxsp_block.h"

typedef struct xsp_proto_handler_t {
	int (**parse) (const void *arg, int remainder, void **msg_body);
	int (**writeout) (void *arg, char *buf, int remainder);
	int (*write_hdr) (void *arg, char *buf);
	uint8_t max_msg_type;
} xspProtoHandler;

int xsp_proto_init();
uint64_t xsp_writeout_msg(char *buf, uint64_t length, xspMsg *msg, xspBlockList *bl);
int xsp_parse_msgbody(const xspMsg *hdr, const void *arg, uint64_t length, void **msg_body);
int xsp_add_proto_handler(uint8_t version, xspProtoHandler *handler);

#endif
