#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <curl/curl.h>
#include <jansson.h>

#include "queue.h"
#include "hashtable.h"
#include "xsp_unis.h"

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

// GLOBALS
static xspUNISConfig config;
// END GLOBALS

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

int xsp_unis_init() {
	const xspSettings *settings;

	settings = xsp_main_settings();

	if (xsp_settings_get_2(settings, "unis", "endpoint", &config.endpoint) != 0) {
		xsp_info(0, "No UNIS endpoint specified!");
		return -1;
	}
	
	if (xsp_settings_get_int_2(settings, "unis", "refresh", &config.refresh_timer) != 0) {
		xsp_info(0, "Refresh time not specified, using default %d", XSP_UNIS_REFRESH_TO);
		config.refresh_timer = XSP_UNIS_REFRESH_TO;
	}

	if (xsp_settings_get_bool_2(settings, "unis", "register", &config.do_register) != 0) {
		config.do_register = 0;
	}

	if (xsp_settings_get_int_2(settings, "unis", "registration_interval", &config.registration_interval) != 0) {
		xsp_info(0, "Refresh time not specified, using default %d", XSP_UNIS_REG_INTERVAL);
		config.registration_interval = XSP_UNIS_REG_INTERVAL;
	}

	if (config.do_register) {
		// start registration thread
		// gets extra config items to build service description
	}
	
	// we could also start a thread that retrieves and caches everything from UNIS
	// for now, every call to the UNIS module will do an active query against the service
	
	return 0;
}

static int xsp_unis_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	// this module doesn't register any option blocks

	return 0;
}
