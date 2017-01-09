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
#ifndef __XSP_PROTO_H
#define __XSP_PROTO_H

#ifndef PACKAGE
#include "config.h"
#endif

#include <sys/types.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#else
#error "Couldn't find standard integer types"
#endif

#define XSP_v0                  0
#define XSP_v1                  1

/* EID types */
enum xsp_eid_types_t {
  XSP_EID_NULL = 0,
  XSP_EID_IPv4,
  XSP_EID_IPv6,
  XSP_EID_URN,
  XSP_EID_HRN,
  XSP_EID_HOPID,
  XSP_EID_DPID,
  XSP_EID_DPIDC
};

enum xsp_sec {
  XSP_SEC_NONE = 0,
  XSP_SEC_SSH,
  XSP_SEC_SSL
};

enum xsp_sess_net_path_actions_t {
  XSP_NET_PATH_CREATE = 0,
  XSP_NET_PATH_DELETE,
  XSP_NET_PATH_MODIFY,
  XSP_NET_PATH_QUERY
};

/* result/status codes */
#define XSP_STAT_OK		0x0000
#define XSP_STAT_NOROUTE        0x0001
#define XSP_STAT_CANT_CONNECT   0x0002
#define XSP_STAT_CLOSING        0xFFFE
#define XSP_STAT_ERROR	        0xFFFF

#define XSP_MAX_LENGTH          65536
#define XSP_MAX_OPT_LENGTH      2**64

#define XSP_HOPID_LEN		63
#define XSP_SESSIONID_LEN	16
#define XSP_PROTO_NAME_LEN      10
#define XSP_AUTH_NAME_LEN       10
#define XSP_NET_PATH_LEN        10

typedef struct xsp_message_hdr_t {
  uint8_t           version;
  uint8_t           type;
  uint16_t          length;
  char              sess_id[XSP_SESSIONID_LEN];
} xspMsgHdr;

/* based on ipv6 addrs */
struct xsp_addr {
  uint8_t            type;

  /* XXX: this needs a proper fix
   * aligning to a 64 bit boundary with xsp_addrc
   * but HOPIDs and HRNs should really not be
   * in this header, limit to 128 bit EIDs
   */
  uint8_t            fill_0;
  uint16_t           fill_1;
  uint32_t           fill_2;

  union {
    uint8_t        xsp_addr8[16];
    uint16_t       xsp_addr16[8];
    uint32_t       xsp_addr32[4];
    uint32_t       xsp_addrs;
    uint64_t       xsp_addrd;
    char           xsp_addrc[XSP_HOPID_LEN+1];
  } xsp_u;
#define x_addr            xsp_u.xsp_addr8
#define x_addr16          xsp_u.xsp_addr16
#define x_addr32          xsp_u.xsp_addr32
#define x_addrs           xsp_u.xsp_addrs
#define x_addrd           xsp_u.xsp_addrd
#define x_addrc           xsp_u.xsp_addrc
};

typedef struct xsp_v1_message_hdr_t {
  uint8_t           version;
  uint8_t           flags;
  uint16_t          type;
  uint16_t          opt_cnt;
  uint16_t          reserved;
  struct xsp_addr   src_eid;
  struct xsp_addr   dst_eid;
  char              sess_id[XSP_SESSIONID_LEN];
} xspv1MsgHdr;

typedef struct xsp_v1_option_hdr_t {
  uint16_t          type;
  uint16_t          sport;
  uint16_t          length;
  uint16_t          reserved;
} xspv1BlockHdr;


/* the XSP socket layer */
#define XSP_SOCKET              2

#endif /* __XSP_PROTO_H */

