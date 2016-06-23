// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
#include <pthread.h>
#include <string.h>

#include "xsp_settings.h"
#include "xsp_main_settings.h"
#include "xsp_logger.h"

static xspSettings *main_settings = NULL;
static pthread_mutex_t main_settings_lock;

int xsp_main_settings_init() {

	if (pthread_mutex_init(&main_settings_lock, 0) != 0) {
		xsp_err(0, "couldn't initialize the main settings lock");
		goto error_exit;
	}

	main_settings = xsp_settings_alloc();
	if (!main_settings) {
		xsp_err(0, "couldn't allocate main settings");
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
		xsp_settings_print(main_settings);
	}
	pthread_mutex_unlock(&main_settings_lock);
}

xspSettings *xsp_main_settings() {
	xspSettings *ret_settings;

	pthread_mutex_lock(&main_settings_lock);
	{
		ret_settings = main_settings;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return ret_settings;
}

int xsp_set_main_settings(xspSettings *settings) {
	pthread_mutex_lock(&main_settings_lock);
	{
		main_settings = settings;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return 0;
}

int xsp_main_settings_get(const char *section, const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_int(const char *section, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_int_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_bool(const char *section, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_bool_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_list(const char *section, const char *option, char ***value, int *count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_list_2(main_settings, section, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_set(const char *section, const char *option, char *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_set_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_set_int(const char *section, const char *option, int value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_set_int_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_set_bool(const char *section, const char *option, int value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_set_bool_2(main_settings, section, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_set_list(const char *section, const char *option, char * const *value, int count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_set_list_2(main_settings, section, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_3(const char *section1, const char *section2, const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_3(main_settings, section1, section2, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_int_3(const char *section1, const char *section2, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_int_3(main_settings, section1, section2, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_bool_3(const char *section1, const char *section2, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_bool_3(main_settings, section1, section2, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_list_3(const char *section1, const char *section2, const char *option, char ***value, int *count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_list_3(main_settings, section1, section2, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_4(const char *section1, const char *section2, const char *section3, const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_4(main_settings, section1, section2, section3, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_int_4(const char *section1, const char *section2, const char *section3, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_int_4(main_settings, section1, section2, section3, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_bool_4(const char *section1, const char *section2, const char *section3, const char *option, int *value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_bool_4(main_settings, section1, section2, section3, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_list_4(const char *section1, const char *section2, const char *section3, const char *option, char ***value, int *count) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get_list_4(main_settings, section1, section2, section3, option, value, count);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_section(const char *section, xspSettings **settings) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings) 
			n = xsp_settings_get_group(main_settings, section, settings);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;

}

int xsp_main_settings_get_subsection(const char *section, const char *subsection, xspSettings **settings) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings) 
			n = xsp_settings_get_group_2(main_settings, section, subsection, settings);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_subsubsection(const char *section, const char *subsection, const char *subsubsection, xspSettings **settings) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings) 
			n = xsp_settings_get_group_3(main_settings, section, subsection, subsubsection, settings);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}

int xsp_main_settings_get_1(const char *option, char **value) {
	int n;

	pthread_mutex_lock(&main_settings_lock);
	{
		if (main_settings)
			n = xsp_settings_get(main_settings, option, value);
		else
			n = -1;
	}
	pthread_mutex_unlock(&main_settings_lock);

	return n;
}


