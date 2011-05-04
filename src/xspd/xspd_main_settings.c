#include <pthread.h>
#include <string.h>

#include "xspd_settings.h"
#include "xspd_main_settings.h"
#include "xspd_logger.h"

static xspdSettings *main_settings = NULL;
static pthread_mutex_t main_settings_lock;

int xspd_main_settings_init() {

	if (pthread_mutex_init(&main_settings_lock, 0) != 0) {
		xspd_err(0, "couldn't initialize the main settings lock");
		goto error_exit;
	}

	main_settings = xspd_settings_alloc();
	if (!main_settings) {
		xspd_err(0, "couldn't allocate main settings");
		goto error_exit_mutex;
	}

	return 0;

error_exit_mutex:
	pthread_mutex_destroy(&main_settings_lock);
error_exit:
	return -1;
}

void print_main_settings() {
	pthread_mutex_lock(&main_settings_lock);
	{
		xspd_settings_print(main_settings);
	}
	pthread_mutex_unlock(&main_settings_lock);
}

xspdSettings *xspd_main_settings() {
	xspdSettings *ret_settings;

	pthread_mutex_lock(&main_settings_lock);
	{
		ret_settings = main_settings;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return ret_settings;
}

int xspd_set_main_settings(xspdSettings *settings) {
	pthread_mutex_lock(&main_settings_lock);
	{
		main_settings = settings;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return 0;
}

int xspd_main_settings_get(const char *section, const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_int(const char *section, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_int_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_bool(const char *section, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_bool_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_list(const char *section, const char *option, char ***value, int *count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_list_2(main_settings, section, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_set(const char *section, const char *option, char *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_set_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_set_int(const char *section, const char *option, int value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_set_int_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_set_bool(const char *section, const char *option, int value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_set_bool_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_set_list(const char *section, const char *option, char * const *value, int count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_set_list_2(main_settings, section, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_set_range(const char *section, const char *option, int min, int max) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_set_range_2(main_settings, section, option, min, max);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_range(const char *section, const char *option, int *min, int *max) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_range_2(main_settings, section, option, min, max);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}


int xspd_main_settings_get_3(const char *section1, const char *section2, const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_3(main_settings, section1, section2, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_int_3(const char *section1, const char *section2, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_int_3(main_settings, section1, section2, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_bool_3(const char *section1, const char *section2, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_bool_3(main_settings, section1, section2, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_list_3(const char *section1, const char *section2, const char *option, char ***value, int *count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_list_3(main_settings, section1, section2, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_range_3(const char *section1, const char *section2, const char *option, int *min, int *max) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_range_3(main_settings, section1, section2, option, min, max);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}


int xspd_main_settings_get_4(const char *section1, const char *section2, const char *section3, const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_4(main_settings, section1, section2, section3, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_int_4(const char *section1, const char *section2, const char *section3, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_int_4(main_settings, section1, section2, section3, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_bool_4(const char *section1, const char *section2, const char *section3, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_bool_4(main_settings, section1, section2, section3, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_list_4(const char *section1, const char *section2, const char *section3, const char *option, char ***value, int *count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get_list_4(main_settings, section1, section2, section3, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_range_4(const char *section1, const char *section2, const char *section3, const char *option, int *min, int *max) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings) 
			n = xspd_settings_get_range_4(main_settings, section1, section2, section3, option, min, max);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_section(const char *section, xspdSettings **settings) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings) 
			n = xspd_settings_get_group(main_settings, section, settings);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;

}

int xspd_main_settings_get_subsection(const char *section, const char *subsection, xspdSettings **settings) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings) 
			n = xspd_settings_get_group_2(main_settings, section, subsection, settings);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_subsubsection(const char *section, const char *subsection, const char *subsubsection, xspdSettings **settings) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings) 
			n = xspd_settings_get_group_3(main_settings, section, subsection, subsubsection, settings);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xspd_main_settings_get_1(const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xspd_settings_get(main_settings, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

