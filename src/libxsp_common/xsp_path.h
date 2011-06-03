#ifndef XSP_PATH_H
#define XSP_PATH_H

#include "xsp_session.h"
#include "xsp_channel.h"

typedef struct xsp_path_t {
	pthread_mutex_t lock;

	pthread_cond_t timeout_cond;

	int tag;

	char *description;

	LIST_HEAD(channellisthead, xsp_channel_t) channel_list;
	
	int (*new_channel) (struct xsp_path_t *path, xspNetPathRule *rule, xspChannel **channel, char **ret_error_msg);
	int (*resize_channel) (struct xsp_path_t *path, xspChannel *channel, uint32_t new_size, char **ret_error_msg);
	int (*close_channel) (struct xsp_path_t *path, xspChannel *channel);

	void (*free) (struct xsp_path_t *path);

	void *path_private;
} xspPath;

xspPath *xsp_alloc_path();
void xsp_free_path(xspPath *path);

#endif
