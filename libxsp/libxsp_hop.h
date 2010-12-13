#ifndef LIBXSP_HOP_H
#define LIBXSP_HOP_H

#ifndef PACKAGE
#include "config.h"
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#include "xsp-proto.h"

typedef struct xsp_hop {
	uint16_t opt_type;
	uint16_t flags;
	char hop_id[XSP_HOPID_LEN + 1];

	char protocol[XSP_PROTO_NAME_LEN + 1];

	struct xsp_sess_info_t *session;

	struct xsp_hop **child;
	int child_count;
} xspHop;

xspHop *xsp_alloc_hop();
void xsp_free_hop(xspHop *hop, int free_children);
int xsp_hop_merge_children(xspHop *dst, xspHop *src);
inline char *xsp_hop_getid(xspHop *hop);
inline void xsp_hop_setid(xspHop *hop, const char *hop_id);
int xsp_hop_add_child(xspHop *parent, xspHop *child);
inline void xsp_hop_set_flag(xspHop *hop, uint16_t flag);
inline int xsp_hop_check_flag(xspHop *hop, uint16_t flag);

#endif
