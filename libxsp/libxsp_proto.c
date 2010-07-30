#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "compat.h"

#include "libxsp.h"
#include "libxsp_proto.h"
#include "libxsp_session.h"
#include "libxsp_hop.h"

int xsp_writeout_msgbody(char *buf, int length, uint8_t version, uint8_t type, void *msg_body);
int libxsp_proto_binary_init();

xspProtoHandler *proto_list[256];

int xsp_add_proto_handler(uint8_t version, xspProtoHandler *handler) {
	proto_list[version] = handler;

	return 0;
}

int xsp_proto_init() {
	return libxsp_proto_binary_init();
}

int xsp_writeout_msg(char *buf, int length, uint8_t version, uint8_t type, char *sess_id, void *msg_body) {
	xspMsgHdr *hdr;
	char *msg_buf;
	int body_length;
	int remainder;

	if (length < sizeof(xspMsgHdr))
		goto write_error;

	hdr = (xspMsgHdr *) buf;
	msg_buf = buf;

	hdr->type = type;
	hdr->version = version;

	if (sess_id != NULL) {
		hex2bin(sess_id, hdr->sess_id, XSP_SESSIONID_LEN * 2);
	} else {
		bzero(hdr->sess_id, XSP_SESSIONID_LEN);
	}

	msg_buf += sizeof(xspMsgHdr);
	remainder = length - sizeof(xspMsgHdr);

	// fill in the message body
	body_length = xsp_writeout_msgbody(msg_buf, remainder, version, type, msg_body);
	if (body_length < 0)
		goto write_error;

	hdr->length = htons(body_length);

	d_printf("body_length: %d %d\n", body_length, ntohs(hdr->length));
	d_printf("header_length: %d\n", sizeof(xspMsgHdr));

	return (sizeof(xspMsgHdr) + body_length);

write_error:
	return -1;
}

int xsp_writeout_msgbody(char *buf, int length, uint8_t version, uint8_t type, void *msg_body) {
	if (proto_list[version] == NULL || proto_list[version]->max_msg_type < type) {
		d_printf("couldn't write: %d %d\n", proto_list[version] == NULL, type);
		return -1;
	}
       
	if (proto_list[version]->writeout[type] == NULL)
		return 0;

	return proto_list[version]->writeout[type](msg_body, buf, length);
}

int xsp_parse_msgbody(const xspMsg *hdr, const char *buf, int length, void **msg_body) {
	int retval;

	if (proto_list[hdr->version] == NULL || proto_list[hdr->version]->max_msg_type < hdr->type) {
		d_printf("bad message type\n");
		retval = -1;
	} else if (proto_list[hdr->version]->parse[hdr->type] == NULL) {
		d_printf("msg contains no message body\n");
		retval = 0;
	} else {
		retval = proto_list[hdr->version]->parse[hdr->type](buf, length, msg_body);
	}

	return retval;
}

void xsp_free_msg(xspMsg *msg) {

	if (msg->msg_body != NULL) {
		switch(msg->type) {
			case XSP_MSG_SESS_NACK:
				free((char *) msg->msg_body);
				break;

			case XSP_MSG_AUTH_TYPE:
				free((xspAuthType *) msg->msg_body);
				break;

			case XSP_MSG_AUTH_TOKEN:
				free((xspAuthToken *) msg->msg_body);
				break;

			case XSP_MSG_SESS_OPEN:
				xsp_free_sess((xspSess *) msg->msg_body);
				break;

			case XSP_MSG_SESS_ACK:
			case XSP_MSG_SESS_CLOSE:
			case XSP_MSG_INVALID:
			default:
				break;
		}
	}

	free(msg);
}
