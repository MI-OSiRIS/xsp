#ifndef LIBXSP_PROTO_BINARY_H
#define LIBXSP_PROTO_BINARY_H

#include "../include/xsp-proto.h"
#include "libxsp.h"
#include "libxsp_proto.h"
#include "libxsp_hop.h"
#include "libxsp_session.h"

int xsp_parse_sess_open_msg(const char *buf, int length, void **msg_body);
xspHop *xsp_parsehop(xspSess *sess, const char *buf, int remainder, int *size);
int xsp_parse_auth_token_msg(const char *buf, int remainder, void **msg_body);
int xsp_parse_auth_type_msg(const char *buf, int remainder, void **msg_body);
int xsp_parse_block_header_msg(const char *buf, int remainder, void **msg_body);
int xsp_parse_nack_msg(const char *buf, int remainder, void **msg_body);
int xsp_parse_data_open_msg(const char *buf, int remainder, void **msg_body);
int xsp_parse_slab_info(const char *buf, int remainder, void **msg_body);
xspSlabRec *xsp_parse_slab_record(const char *buf, int remainder, int *size);

int xsp_writeout_sess_open_msg(void *hop, char *buf, int remainder);
int xsp_writeouthop(xspHop *hop, char *buf, int remainder);
int xsp_writeout_auth_token_msg(void *arg, char *buf, int remainder);
int xsp_writeout_auth_type_msg(void *arg, char *buf, int remainder);
int xsp_writeout_block_header_msg(void *arg, char *buf, int remainder);
int xsp_writeout_nack_msg(void *arg, char *buf, int remainder);
int xsp_writeout_data_open_msg(void *arg, char *buf, int remainder);
int xsp_writeout_slab_info(void *arg, char *buf, int remainder);
int xsp_writeout_slab_record(xspSlabRec *rec, char *buf, int remainder);


typedef struct xsp_msg_data_open_hdr_t {
	uint32_t flags;
	char hop_id[XSP_HOPID_LEN];
	char proto[XSP_PROTO_NAME_LEN];
} xspDataOpen_HDR;

typedef struct xsp_hop_hdr_t {
	char id[XSP_HOPID_LEN];
	char protocol[XSP_PROTO_NAME_LEN];
	uint32_t flags;
	uint16_t child_count;
} xspHop_HDR;

typedef struct xsp_sess_hdr_t {
	char sess_id[XSP_SESSIONID_LEN];
	char src_id[XSP_HOPID_LEN];
	uint32_t sess_flags;
	uint32_t hop_flags;
} xspSess_HDR;

typedef struct xsp_msg_auth_token_hdr_t {
	uint32_t token_length;
} xspAuthToken_HDR;

typedef struct xsp_msg_auth_info_hdr_t {
	char name[XSP_AUTH_NAME_LEN];
} xspAuthType_HDR;

typedef struct xsp_block_header_hdr_t {
	uint16_t type;
	uint16_t sport;
	uint32_t length;
} xspBlockHeader_HDR;

typedef struct xsp_msg_sess_nack_hdr_t {
	uint32_t length;
} xspSessNack_HDR;

typedef struct slab_record_hdr_t {
        char sess_id[XSP_SESSIONID_LEN];
        uint32_t offset;
        uint32_t length;
        uint32_t crc;
} xspSlabRec_HDR;

typedef struct slabs_info_hdr_t {
        uint32_t length;
        uint32_t rec_count;
} xspSlabInfo_HDR;

#endif
