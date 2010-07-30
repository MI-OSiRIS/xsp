/*
 * $Id: libxsp.h,v 1.3.2.5.2.3 2005/04/08 00:24:36 aaron Exp $
 */

#ifndef __LIBXSP_H
#define __LIBXSP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef DEBUG
#define d_printf(fmt, args...) fprintf(stderr, "XSP:"fmt, ##args)
#else
#define d_printf(fmt, args...)
#endif

#include "xsp-proto.h"
#include "libxsp_session.h"
#include "libxsp_hop.h"
#include "libxsp_path.h"

/* XSP Defines */

#define XSP_MSG_NOWAIT 0x01

#define XSP_SESS_SAVE_STREAM	0x01
#define XSP_SESS_LSRR		0x02

#define XSP_HOP_NATIVE 	0x01
#define XSP_UNNECESSARY	0x02

#define XSP_MSG_INVALID			0
#define XSP_MSG_SESS_OPEN		1
#define XSP_MSG_SESS_ACK		2
#define XSP_MSG_SESS_CLOSE		3
#define XSP_MSG_BLOCK_HEADER		4
#define XSP_MSG_AUTH_TYPE		8
#define XSP_MSG_AUTH_TOKEN		9
#define XSP_MSG_SESS_NACK		10
#define XSP_MSG_PING			11
#define XSP_MSG_PONG			12
#define XSP_MSG_DATA_OPEN               13
#define XSP_MSG_DATA_CLOSE              14
#define XSP_MSG_PATH_OPEN               15
#define XSP_MSG_PATH_CLOSE              16

/* XSP Objects */

typedef struct xsp_message_t {
	uint8_t type;
	uint8_t version;
	char sess_id[XSP_SESSIONID_LEN * 2 + 1];
	void *msg_body;
} xspMsg;

typedef struct xsp_authorization_type_t {
	char name[XSP_AUTH_NAME_LEN];
} xspAuthType;

typedef struct xsp_auth_token_t {
	size_t token_length;
	void *token;
} xspAuthToken;

typedef struct xsp_block_header_t {
	uint32_t length;
	void *blob;
} xspBlockHeader;

typedef struct xsp_data_open_header_t {
	char hop_id[XSP_HOPID_LEN];
	uint16_t flags;
} xspDataOpenHeader;

/* XSP Functions */
int xsp_init();
void xsp_free_msg(xspMsg *msg);

struct addrinfo *xsp_lookuphop(const char *hop_id);

char *xsp_sa2hopid(const struct sockaddr *sa, SOCKLEN_T sa_len, int resolve);

char *xsp_sa2hopid_r(const struct sockaddr *sa, SOCKLEN_T sa_len, char *output_buf, size_t buflen, int resolve);

int xsp_make_connection(char *hop_id);

int xsp_parse_hopid(const char *hop_id, char **ret_server, char **ret_port);

int gen_rand_hex(char *output_buf, int size);

long gen_rand_seed();

#endif /* __LIBXSP_H */
