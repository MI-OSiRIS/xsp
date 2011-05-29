#ifndef LIBXSP_PROTO_BINARY_V0_H
#define LIBXSP_PROTO_BINARY_V0_H

#include "../include/xsp-proto.h"
#include "libxsp.h"
#include "libxsp_proto.h"
#include "libxsp_hop.h"
#include "libxsp_session.h"

static int xsp_writeout_hdr(void *arg, char *buf);

static int xsp_parse_sess_open_msg(const void *arg, int length, void **msg_body);
static xspHop *xsp_parsehop(xspSess *sess, const void *arg, int remainder, int *size);
static int xsp_parse_auth_token_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_auth_type_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_block_header_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_nack_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_slab_info(const void *arg, int remainder, void **msg_body);
static xspSlabRec *xsp_parse_slab_record(const void *arg, int remainder, int *size);

static int xsp_writeout_sess_open_msg(void *hop, char *buf, int remainder);
static int xsp_writeouthop(xspHop *hop, char *buf, int remainder);
static int xsp_writeout_auth_token_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_auth_type_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_block_header_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_nack_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_slab_info(void *arg, char *buf, int remainder);
static int xsp_writeout_slab_record(xspSlabRec *rec, char *buf, int remainder);

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

typedef struct xsp_block_hdr_t {
	uint16_t type;
	uint16_t sport;
	uint32_t length;
} xspBlock_HDR;

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
