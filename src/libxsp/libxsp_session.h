#ifndef LIBXSP_SESSION_H
#define LIBXSP_SESSION_H

#include "libxsp_hop.h"
#include "xsp-proto.h"

typedef struct xsp_sess_info_t {
	char sess_id[2*XSP_SESSIONID_LEN + 1];

	struct xsp_addr src_eid;
	struct xsp_addr dst_eid;

	uint32_t sess_flags;
	uint32_t hop_flags;

	xspHop **child;
	int child_count;
} xspSess;

xspSess *xsp_alloc_sess();
void xsp_free_sess(xspSess *sess);
int xsp_sess_addhop(xspSess *sess, xspHop *hop);
char *xsp_sessid2str(const char *sess_id, char *output_buf, int size);
int xsp_sesscmp(xspSess *s1, xspSess *s2);

#endif
