// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
#ifndef LIBXSP_PROTO_BINARY_H
#define LIBXSP_PROTO_BINARY_H

#include "../include/xsp-proto.h"
#include "libxsp.h"
#include "libxsp_proto.h"
#include "libxsp_hop.h"
#include "libxsp_session.h"

static int xsp_writeout_hdr(void *arg, char *buf);
static int xsp_writeout_block_hdr(void *arg, char *buf, int remainder);

static int xsp_parse_default_block_list(const void *arg, int length, void **msg_body);
static int xsp_writeout_default_block_list(void *arg, char *buf, int remainder);
static int xsp_parse_app_data_block_list(const void *arg, int length, void **msg_body);
static int xsp_writeout_app_data_block_list(void *arg, char *bug, int remainder);

static int xsp_parse_hops(const void *arg, int remainder, void **msg_body);
static xspHop *xsp_parsehop(xspSess *sess, void *arg, int remainder, int *size);
static int xsp_parse_auth_token_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_auth_type_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_block_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_nack_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_data_chan_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_net_path_msg(const void *arg, int remainder, void **msg_body);
static int xsp_parse_slab_info(const void *arg, int remainder, void **msg_body);
static xspSlabRec *xsp_parse_slab_record(const void *arg, int remainder, int *size);

static int xsp_writeout_hops(void *arg, char *buf, int remainder);
static int xsp_writeouthop(xspHop *hop, char *buf, int remainder);
static int xsp_writeout_auth_token_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_auth_type_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_block_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_nack_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_data_chan_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_net_path_msg(void *arg, char *buf, int remainder);
static int xsp_writeout_slab_info(void *arg, char *buf, int remainder);
static int xsp_writeout_slab_record(xspSlabRec *rec, char *buf, int remainder);

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
  uint32_t hop_flags;
} xspSessOpen_HDR;

typedef struct xsp_msg_auth_token_hdr_t {
  uint32_t token_length;
} xspAuthToken_HDR;

typedef struct xsp_msg_auth_info_hdr_t {
  char name[XSP_AUTH_NAME_LEN];
} xspAuthType_HDR;

typedef struct xsp_msg_sess_nack_hdr_t {
  uint32_t length;
} xspSessNack_HDR;

typedef struct xsp_sess_net_path_hdr_t {
  uint16_t action;
  uint16_t rule_count;
} xspNetPath_HDR;

typedef struct slab_record_hdr_t {
  char sess_id[XSP_SESSIONID_LEN];
  uint16_t flags;
  uint32_t offset;
  uint32_t length;
  uint32_t crc;
  union {
    struct xsp_rdma_mr_t mr;
  } rdma;
} xspSlabRec_HDR;

typedef struct slabs_info_hdr_t {
  uint32_t seq;
  uint32_t length;
  uint32_t rec_count;
} xspSlabInfo_HDR;

#endif
