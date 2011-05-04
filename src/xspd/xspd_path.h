#ifndef XSPD_PATH_H
#define XSPD_PATH_H

#include "xspd_session.h"
#include "xspd_channel.h"

typedef struct xspd_path_t {
	pthread_mutex_t lock;

	pthread_cond_t timeout_cond;

	int tag;

	char *description;

	LIST_HEAD(channellisthead, xspd_channel_t) channel_list;

	int (*new_channel) (struct xspd_path_t *path, uint32_t size, xspdChannel **channel, char **ret_error_msg);
	int (*resize_channel) (struct xspd_path_t *path, xspdChannel *channel, uint32_t new_size, char **ret_error_msg);
	int (*close_channel) (struct xspd_path_t *path, xspdChannel *channel);

	void (*free) (struct xspd_path_t *path);

	void *path_private;
} xspdPath;

xspdPath *xspd_alloc_path();
void xspd_free_path(xspdPath *path);

#endif
