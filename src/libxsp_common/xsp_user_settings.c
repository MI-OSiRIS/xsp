#include <pthread.h>
#include <string.h>

#include "xsp_settings.h"
#include "xsp_user_settings.h"
#include "xsp_logger.h"
#include "hashtable.h"

static int xsp_usrplcy_htable_equal(const void *k1, const void *k2);
static unsigned int xsp_usrplcy_htable_hash(const void *k1);

static struct hashtable *incoming_table;
static struct hashtable *outgoing_table;
static struct hashtable *both_table;
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

int xsp_user_settings_init() {
	incoming_table = create_hashtable(10, xsp_usrplcy_htable_hash, xsp_usrplcy_htable_equal);
	if (!incoming_table) {
		xsp_err(0, "couldn't allocate hashtable");
		goto error_exit;
	}

	outgoing_table = create_hashtable(10, xsp_usrplcy_htable_hash, xsp_usrplcy_htable_equal);
	if (!outgoing_table) {
		xsp_err(0, "couldn't allocate hashtable");
		goto error_exit_incoming;
	}

	both_table = create_hashtable(10, xsp_usrplcy_htable_hash, xsp_usrplcy_htable_equal);
	if (!both_table) {
		xsp_err(0, "couldn't allocate hashtable");
		goto error_exit_incoming;
	}
	
	return 0;

error_exit_incoming:
	hashtable_destroy(incoming_table, 0);
error_exit:
	return -1;
}

xspSettings *xsp_user_settings(const char *user, enum xsp_direction_t direction) {
	xspSettings *ret_settings;

	pthread_mutex_lock(&table_lock);
	{
		switch (direction) {
			case XSP_INCOMING:
				ret_settings = hashtable_search(incoming_table, user);
				break;

			case XSP_OUTGOING:
				ret_settings = hashtable_search(outgoing_table, user);
				break;

			case XSP_BOTH:
				ret_settings = hashtable_search(both_table, user);
				break;

			default:
				ret_settings = NULL;
				break;
		}

	}
	pthread_mutex_unlock(&table_lock);

	return ret_settings;
}

int xsp_set_user_settings(char *user, enum xsp_direction_t direction, xspSettings *settings) {
	xspSettings *old_settings;
	int retval;

	pthread_mutex_lock(&table_lock);
	{
		switch (direction) {
			case XSP_INCOMING:
				old_settings = hashtable_remove(incoming_table, user);
				retval = hashtable_insert(incoming_table, strdup(user), settings);
				break;

			case XSP_OUTGOING:
				old_settings = hashtable_remove(outgoing_table, user);
				retval = hashtable_insert(outgoing_table, strdup(user), settings);
				break;

			case XSP_BOTH:
				old_settings = hashtable_remove(both_table, user);
				retval = hashtable_insert(both_table, strdup(user), settings);
				break;

			default:
				retval = -1;
				break;
		}
	}
	pthread_mutex_unlock(&table_lock);

	return retval;
}


static int xsp_usrplcy_htable_equal(const void *k1, const void *k2) {
	const char *s1, *s2;

	s1 = k1;
	s2 = k2;

	return (strcasecmp(s1, s2) == 0);
}

static unsigned int xsp_usrplcy_htable_hash(const void *k1) {
	const char *s1 = k1;
	unsigned int res;
	int i;

	res = 0;

	for(i = 0; i < strlen(s1); i++) {
		res += s1[i];
	}

	return res;
}
