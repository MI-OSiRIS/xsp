#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include "xspd_path.h"

#include "compat.h"

xspdPath *xspd_alloc_path() {
	xspdPath *path;

	path = malloc(sizeof(xspdPath));
	if (!path)
		goto error_exit;

	bzero(path, sizeof(xspdPath));

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

void xspd_free_path(xspdPath *path) {
	pthread_mutex_destroy(&(path->lock));
	if (path->description)
		free(path->description);
	free(path);
}
