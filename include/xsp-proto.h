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

/* XSP message types */

/* result/status codes */
#define XSP_STAT_OK		0x0000
#define XSP_STAT_NOROUTE        0x0001
#define XSP_STAT_CANT_CONNECT   0x0002
#define XSP_STAT_CLOSING        0xFFFE
#define XSP_STAT_ERROR	        0xFFFF

#define XSP_MAX_LENGTH          65536
#define XSP_MAX_OPT_LENGTH      2**64

#define XSP_HOPID_LEN		60
#define XSP_EID_LEN             16
#define XSP_SESSIONID_LEN	16
#define XSP_PROTO_NAME_LEN      10
#define XSP_AUTH_NAME_LEN       10

typedef struct xsp_message_hdr_t {
	uint16_t          length;
	uint8_t           version;
	uint8_t           type;
	char              sess_id[XSP_SESSIONID_LEN];
} xspMsgHdr;

/* based on ipv6 addrs */
struct xsp_addr {
	union {
		uint8_t   xsp_addr8[16];
		uint16_t  xsp_addr16[8];
		uint32_t  xsp_addr32[4];
		char      xsp_addrc[128];
	} xsp_u;
#define x_addr            xsp_u.xsp_addr8
#define x_addr16          xsp_u.xsp_addr16
#define x_addr32          xsp_u.xsp_addr32
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
} xspv1BlockHdr;
	
	
/* the XSP socket layer */
#define XSP_SOCKET              2

#endif /* __XSP_PROTO_H */

