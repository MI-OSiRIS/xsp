#ifndef XSPD_CHANNEL_H
#define XSPD_CHANNEL_H

#include "config.h"

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif


#include "queue.h"


typedef struct xspd_channel_t {
	uint32_t bandwidth;
	int vlan;
	LIST_ENTRY(xspd_channel_t) path_entries;
	LIST_HEAD(pathlisthead, xspd_connection_t) connlist;
} xspdChannel;

xspdChannel *xspd_alloc_channel();
void xspd_free_channel(xspdChannel* channel);

#endif
