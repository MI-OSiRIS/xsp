/*
 * $Id: xsp-proto.h,v 1.1.1.1.4.2.2.1 2005/04/06 15:35:28 aaron Exp $
 */

#ifndef __XSP_PROTO_H
#define __XSP_PROTO_H

#include "config.h"

#include <sys/types.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#else
#error "Couldn't find standard integer types"
#endif


/* XSP message types */

/* result/status codes */
#define XSP_STAT_OK		0x0000
#define XSP_STAT_NOROUTE 0x0001
#define XSP_STAT_CANT_CONNECT 0x0002
#define XSP_STAT_CLOSING 0xFFFE
#define XSP_STAT_ERROR	0xFFFF

#define XSP_MAX_LENGTH	65536

#define XSP_HOPID_LEN		60
#define XSP_SESSIONID_LEN	16
#define XSP_PROTO_NAME_LEN      10
#define XSP_AUTH_NAME_LEN      10

typedef struct xsp_message_hdr_t {
	uint16_t length;
	uint8_t version;
	uint8_t type;
	char sess_id[XSP_SESSIONID_LEN];
} xspMsgHdr;

/* the XSP socket layer */
#define XSP_SOCKET      2

#endif /* __XSP_PROTO_H */

