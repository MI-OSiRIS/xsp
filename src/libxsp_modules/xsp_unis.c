#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <jansson.h>

#include "queue.h"
#include "hashtable.h"
#include "xsp_unis.h"
#include "unis_registration.h"
#include "libunis_c_log.h"

#include "xsp_session.h"
#include "xsp_tpool.h"
#include "xsp_listener.h"
#include "xsp_settings.h"
#include "xsp_main_settings.h"
#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_protocols.h"
#include "xsp_config.h"
#include "xsp_auth.h"
#include "xsp_modules.h"
#include "libconfig.h"

/* GLOBALS */
static unis_config config;
/* END GLOBALS */

int xsp_unis_init();
static int xsp_unis_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);

xspModule xsp_unis_module = {
	.desc = "UNIS Module",
        .dependencies = "",
	.init = xsp_unis_init,
	.opt_handler = xsp_unis_opt_handler
};

xspModule *module_info() {
	return &xsp_unis_module;
}
int xsp_unis_parse_listener_config(const xspSettings *settings, 
				   char **listener_names, int listener_count)
{
    int          i = 0;
    int          port;
    unsigned int is_disabled;
    service_listener *listener;
    config.listeners = malloc(listener_count*sizeof(service_listener));
    listener = config.listeners;
    config.listener_count = listener_count;
    for (i = 0; i < listener_count ; i++)
    {
	if (xsp_settings_get_int_3(settings, "listeners", listener_names[i],
				   "port", &listener->port) != 0) {
	    listener->is_disabled=0;
	}
	listener->protocol_name = listener_names[i];
	listener++;
    }
    return 0;
}
int xsp_unis_parse_config(const xspSettings *settings)
{
    char **listener_names;
    int listener_count;

    if (xsp_settings_get_2(settings, "unis",
			   "name", &config.name) != 0) {
	xsp_info(0, "No UNIS name specified!");

    }
    if (xsp_settings_get_2(settings, "unis",
			   "type", &config.type) != 0) {
	xsp_info(0, "No UNIS type specified!");

    }
    if (xsp_settings_get_2(settings, "unis",
			   "endpoint", 
			   &config.endpoint) != 0) {
	xsp_info(0, "No UNIS endpoint specified!");
	return -1;

    }
    if (xsp_settings_get_2(settings, "unis",
			   "protocol_name",
			   &config.protocol_name) != 0) {
	xsp_info(0, "No UNIS type specified!");

    }
    if (xsp_settings_get_2(settings, "unis",
			   "publicip", &config.iface) != 0) {
        xsp_info(0, "No UNIS publicip specified!");

    }
    if (xsp_settings_get_int_2(settings, "unis",
			       "port", &config.port) != 0) {
	xsp_info(0, "No UNIS publicport specfied");

    }
    if (xsp_settings_get_bool_2(settings, "unis",
				"register", 
				&config.do_register) != 0) {
	xsp_info(0, "Unis do_register flag missing");

    }
    if (xsp_settings_get_int_2(settings, "unis",
			       "registration_interval", 
			       &config.registration_interval) != 0) {
	xsp_info(0, 
		 "Registration interval not specified, using default %d",
		 UNIS_REG_INTERVAL);
	config.registration_interval = UNIS_REG_INTERVAL;
    }
    if (xsp_settings_get_int_2(settings, "unis", "refresh",
			       &config.refresh_timer) != 0) {
	xsp_info(0, 
		 "Refresh time not specified, using default %d",
		 UNIS_REFRESH_TO);
	config.refresh_timer = UNIS_REFRESH_TO;
    }
    if(xsp_settings_get_section_names(settings,
				      "listeners", &listener_names)!=0) {
	printf("Listeners group not found \n");
	return -1;
    }
    xsp_settings_get_no_section(settings, "listeners", &listener_count);
    config.listener_count = 0;
    xsp_unis_parse_listener_config(settings, listener_names, listener_count);
    return 0;
}


int xsp_unis_init() {
	const xspSettings *settings;

	settings = xsp_main_settings();
	if (xsp_unis_parse_config(settings) == -1) {
	    fprintf(stderr, "Parsing unis registartion config failed\n");
	    return -1;
	}
	if(config.do_register) {
	    if(unis_init(&config) == 0) {
		xsp_info(0, "register_unis: unis registration is successful.");
		return 0;
	    } else {
		xsp_info(0, "register_unis: error in unis registration.");
		return -1;
	    }
	}
	
	return 0;
}

static int xsp_unis_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	/* this module doesn't register any option blocks */

	return 0;
}

