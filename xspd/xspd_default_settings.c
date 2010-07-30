#include <pthread.h>
#include <string.h>

#include "xspd_settings.h"
#include "xspd_default_settings.h"
#include "xspd_logger.h"

static xspdSettings *incoming_default_settings = NULL;
static xspdSettings *outgoing_default_settings = NULL;
static xspdSettings *both_default_settings = NULL;
static pthread_mutex_t default_settings_lock;

int xspd_default_settings_init() {

	if (pthread_mutex_init(&default_settings_lock, 0) != 0) {
		xspd_err(0, "couldn't initialize the default settings lock");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

xspdSettings *xspd_default_settings(enum xspd_direction_t direction) {
	xspdSettings *ret_settings;

	pthread_mutex_lock(&default_settings_lock);
	{
		switch (direction) {
			case XSPD_INCOMING:
				ret_settings = incoming_default_settings;
				break;
			case XSPD_OUTGOING:
				ret_settings = outgoing_default_settings;
				break;
			case XSPD_BOTH:
				ret_settings = both_default_settings;
				break;
			default:
				ret_settings = NULL;
				break;
		}
	}
	pthread_mutex_unlock(&default_settings_lock);

	return ret_settings;
}

int xspd_set_default_settings(xspdSettings *settings, enum xspd_direction_t direction) {
	int retval;

	pthread_mutex_lock(&default_settings_lock);
	{
		switch (direction) {
			case XSPD_INCOMING:
				incoming_default_settings = settings;
				retval = 0;
				break;
			case XSPD_OUTGOING:
				outgoing_default_settings = settings;
				retval = 0;
				break;
			case XSPD_BOTH:
				both_default_settings = settings;
				retval = 0;
				break;
			default:
				retval = -1;
				break;
		}
	}
	pthread_mutex_unlock(&default_settings_lock);

	return retval;
}
