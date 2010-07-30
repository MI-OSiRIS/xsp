#ifndef LIBXSP_PROTOCOL_H
#define LIBXSP_PROTOCOL_H

#include "libxsp.h"

typedef struct xsp_proto_handler_t {
	int (**parse) (const char *buf, int remainder, void **msg_body);
	int (**writeout) (void *arg, char *buf, int remainder);
	uint8_t max_msg_type;
} xspProtoHandler;

int xsp_proto_init();
int xsp_writeout_msg(char *buf, int length, uint8_t version, uint8_t type, char *sess_id, void *msg_body);
int xsp_parse_msgbody(const xspMsg *hdr, const char *buf, int length, void **msg_body);
int xsp_add_proto_handler(uint8_t version, xspProtoHandler *handler);

#endif
