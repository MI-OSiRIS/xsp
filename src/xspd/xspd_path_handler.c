#include <string.h>

#include "hashtable.h"

#include "xspd_config.h"
#include "xspd_logger.h"
#include "xspd_path.h"
#include "xspd_path_handler.h"

static xspdPathHandler *path_handlers[255];

static struct hashtable *path_list;
static pthread_mutex_t path_list_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned int xspd_path_hash_str(const void *k1);
static int xspd_path_hash_equal(const void *k1, const void *k2);

int xspd_path_handler_init() {
	path_list = create_hashtable(7, xspd_path_hash_str, xspd_path_hash_equal);
	if (!path_list)
		return -1;

	bzero(path_handlers, sizeof(xspdPathHandler *) * 255);

	return 0;
}

int xspd_get_path_handler(const char *name) {
	uint8_t i;

	for(i = 0;  i < 255; i++) {
		if (path_handlers[i] != NULL) {
			if (strcasecmp(path_handlers[i]->name, name) == 0)
				return i;
		}
	}

	return -1;
}

int xspd_add_path_handler(xspdPathHandler *handler) {
	uint8_t i;

	for(i = 0;  i < 255; i++) {
		if (path_handlers[i] != NULL) {
			if (strcasecmp(path_handlers[i]->name, handler->name) == 0)
				break;
		} else {
			break;
		}
	}

	if (i == 255) {
		return -1;
	}

	path_handlers[i] = handler;

	return 0;
}

static unsigned int xspd_path_hash_str(const void *k1) {
	const char *c = k1;
	unsigned int retval;

	retval = 0;

	while(*c != 0) {
		retval += *c;
		c++;
	}

	return retval;
}

static int xspd_path_hash_equal(const void *k1, const void *k2) {
	const char *s1, *s2;

	s1 = k1;
	s2 = k2;

	while(s1 != 0 && s2 != 0 && s1 == s2) {
		s1++;
		s2++;
	}

	if (s1 == 0 && s2 == 0)
		return 0;

	return -1;
}

int xspd_get_path(const char *type, xspdSettings *settings, xspdPath **ret_path, char **ret_error_msg) {
	xspdPath *path;
	int num;
	char *path_id;
	char *error_msg;

	num = xspd_get_path_handler(type);
	if (num < 0) {
		xspd_err(0, "requested path has invalid type: %s", type);
		goto error_exit;
	}

	path_id = path_handlers[num]->get_path_id(settings, &error_msg);
	if (!path_id) {
		xspd_err(0, "error finding path identifier for path of type %s: %s", type, error_msg);
		if (ret_error_msg)
			*ret_error_msg = error_msg;

		goto error_exit;
	}

	pthread_mutex_lock(&path_list_lock);
	{
		path = hashtable_search(path_list, path_id);
		if (!path) {
			if (path_handlers[num]->allocate(settings, &path, &error_msg) != 0) {
				xspd_err(0, "couldn't create new path element of type %s: %s", type, error_msg);
				if (ret_error_msg)
					*ret_error_msg = error_msg;

				goto error_exit_unlock;
			}

			path->description = path_id;

			if (hashtable_insert(path_list, strdup(path_id), path) == 0) {
				xspd_err(0, "couldn't save reference to %s", path_id);
				if (ret_error_msg)
					*ret_error_msg = strdup("Couldn't save path reference");

				goto error_exit_path;
			}
		}
	}
	pthread_mutex_unlock(&path_list_lock);

	*ret_path = path;

	return 0;

error_exit_path:
	path->free(path);
error_exit_unlock:
	pthread_mutex_unlock(&path_list_lock);
error_exit:
	return -1;
}