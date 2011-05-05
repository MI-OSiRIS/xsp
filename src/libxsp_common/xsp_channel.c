#include <stdlib.h>
#include <strings.h>

#include "xsp_channel.h"

xspChannel *xsp_alloc_channel() {
	xspChannel *channel;
	
	channel = malloc(sizeof(xspChannel));
	if (!channel)
		goto error_exit;

	bzero(channel, sizeof(xspChannel));

	return channel;

 error_exit:
	return NULL;
}

void xsp_free_channel(xspChannel* channel) {
	free(channel);
}
