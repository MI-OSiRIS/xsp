#include <stdlib.h>
#include <strings.h>

#include "xspd_channel.h"

xspdChannel *xspd_alloc_channel() {
	xspdChannel *channel;

	channel = malloc(sizeof(xspdChannel));
	if (!channel)
		goto error_exit;

	bzero(channel, sizeof(xspdChannel));

	return channel;

error_exit:
	return NULL;
}

void xspd_free_channel(xspdChannel* channel) {
	free(channel);
}
