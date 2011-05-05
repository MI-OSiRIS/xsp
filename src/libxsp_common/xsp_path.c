#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include "xsp_path.h"

#include "compat.h"

xspPath *xsp_alloc_path() {
	xspPath *path;

	path = malloc(sizeof(xspPath));
	if (!path)
		goto error_exit;

	bzero(path, sizeof(xspPath));

	if (pthread_mutex_init(&(path->lock), NULL) != 0)
		goto error_exit2;

	if (pthread_cond_init(&(path->timeout_cond), NULL) != 0)
		goto error_exit2;


	return path;

error_exit2:
	free(path);
error_exit:
	return NULL;
}

void xsp_free_path(xspPath *path) {
	pthread_mutex_destroy(&(path->lock));
	if (path->description)
		free(path->description);
	free(path);
}
