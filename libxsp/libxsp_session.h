#ifndef LIBXSP_SESSION_H
#define LIBXSP_SESSION_H

#include "libxsp_hop.h"
#include "xsp-proto.h"

typedef struct xsp_sess_info_t {
	char sess_id[XSP_SESSIONID_LEN * 2 + 1];

	char src_id[XSP_HOPID_LEN + 1];

	uint32_t sess_flags;

	uint32_t hop_flags;

	xspHop **child;
	int child_count;
} xspSess;

xspSess *xsp_alloc_sess();
void xsp_free_sess(xspSess *sess);
int xsp_sess_addhop(xspSess *sess, xspHop *hop);
char *xsp_sessid2str(const char *sess_id, char *output_buf, int size);

#endif
