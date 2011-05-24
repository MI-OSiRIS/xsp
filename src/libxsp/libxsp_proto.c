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
int libxsp_proto_binary_v0_init();
int libxsp_proto_binary_v1_init();

xspProtoHandler *proto_list[256];

int xsp_add_proto_handler(uint8_t version, xspProtoHandler *handler) {
	d_printf("adding protocol handler [%d]\n", version);
	proto_list[version] = handler;

	return 0;
}

int xsp_proto_init() {
	int ret;
	
	ret = libxsp_proto_binary_v0_init();
	if (ret < 0) {
		d_printf("could not start XSP v0 handler\n");
		goto error_exit;
	}

	ret = libxsp_proto_binary_v1_init();
	if (ret < 0) {
		d_printf("could not start XSP v1 handler\n");
		goto error_exit;
	}
	
	return 0;

 error_exit:
	return -1;
}

int xsp_writeout_msg(char *buf, int length, int version, int type, void *msg, void *msg_body) {
	char *msg_buf;
	int body_length;
	int hdr_length;
	int remainder;

	if (!msg || length < sizeof(xspMsgHdr))
		goto write_error;

	if (proto_list[version] == NULL) {
		d_printf("unknown version: %d %d\n", version, type);
		goto write_error;
	}
	
	if (proto_list[version]->write_hdr == NULL) {
		d_printf("write_hdr not defined: %d %d\n", version, type);
		goto write_error;
	}

	msg_buf = buf;

	d_printf("about to write v%d hdr\n", version);

	hdr_length = proto_list[version]->write_hdr(msg, msg_buf);
	
	if (hdr_length <= 0) {
		d_printf("error writing header: %d %d\n", version, type);
		goto write_error;
	}
	
	msg_buf += hdr_length;
	remainder = length - hdr_length;

	/* fill in the message body */
	body_length = xsp_writeout_msgbody(msg_buf, remainder, version, type, msg_body);
	if (body_length < 0)
		goto write_error;

	/* XXX: v0 requires the body length in the header */
	if (version == XSP_v0) {
		xspMsgHdr *hdr = (xspMsgHdr*)buf;
		hdr->length = htons(body_length);
		d_printf("v0 hdr length: %d\n", ntohs(hdr->length));
	}

	d_printf("body_length: %d\n", body_length);
	d_printf("header_length: %d\n", hdr_length);

	return hdr_length + body_length;

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
	    d_printf("bad message type: %d\n", hdr->type);
		retval = -1;
	} else if (proto_list[hdr->version]->parse[hdr->type] == NULL) {
	        d_printf("msg of type [%d] contains no message body\n", hdr->type);
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

		        case XSP_MSG_APP_DATA:
				if (((xspBlock *) msg->msg_body)->data)
					free(((xspBlock *) msg->msg_body)->data);
				free(msg->msg_body);
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
