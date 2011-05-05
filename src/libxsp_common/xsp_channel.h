#ifndef XSP_CHANNEL_H
#define XSP_CHANNEL_H

#include "config.h"

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif


#include "queue.h"


typedef struct xsp_channel_t {
	uint32_t bandwidth;
	int vlan;
	LIST_ENTRY(xsp_channel_t) path_entries;
	LIST_HEAD(pathlisthead, xsp_connection_t) connlist;
} xspChannel;

xspChannel *xsp_alloc_channel();
void xsp_free_channel(xspChannel* channel);

#endif
