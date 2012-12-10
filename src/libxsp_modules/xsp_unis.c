#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <jansson.h>

#include "queue.h"
#include "hashtable.h"
#include "xsp_unis.h"
#include "xsp_curl_context.h"

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

/* GLOBALS */
static xspUNISConfig config;
static xspCURLContext curl_context;
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
		xsp_info(0, "Registration interval not specified, using default %d", XSP_UNIS_REG_INTERVAL);
		config.registration_interval = XSP_UNIS_REG_INTERVAL;
	}

	if (config.do_register) {
		/* start registration thread
		   gets extra config items to build service description 
		   there are some rough examples in misc/json */
	}
	
	/* we could also start a thread that retrieves and caches everything from UNIS
	   for now, every call to the UNIS module will do an active query against the service */
	

	curl_context.url = config.endpoint;
        curl_context.use_ssl = 0;
        curl_context.curl_persist = 0;

        if (xsp_init_curl(&curl_context, NULL) != 0) {
                xsp_info(0, "Could not start CURL context");
                return -1;
        }

	return 0;
}

static int xsp_unis_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	/* this module doesn't register any option blocks */

	return 0;
}

int xsp_unis_get_service_access_points(char *sname, char ***ret_aps, int *num_aps) {
	json_t *json_ret;;
	json_error_t json_err;
	char *query;
	char *response;
	char **aps;
	int num_objs;

	if (!ret_aps || !num_aps)
		return -1;

	asprintf(&query, "/services?serviceType=%s", sname);

	xsp_curl_json_string(&curl_context,
                             query,
                             CURLOPT_HTTPGET,
                             NULL,
                             &response);

	json_ret = json_loads(response, 0, &json_err);
        if (!json_ret) {
                xsp_info(5, "Could not decode response: %d: %s", json_err.line, json_err.text);
		return -1;
        }

	free(query);
	free(response);
	
	num_objs = json_array_size(json_ret);
	if (num_objs == 0) {
		ret_aps = NULL;
		*num_aps = 0;
		return 0;
	}
	else {
		aps = (char**)malloc(num_objs*sizeof(char*));
		*num_aps = num_objs;
	}
	
	/* now we extract the fields we want

	   this gets more complicated because updates to UNIS will generate similar
	   entries with more recent timestamps.  we should get only the most recent
	   entry for a particular UNIS object. more parsing... */
	
	int i;
	json_t *obj;
	json_t *key;

	//printf("JSON_RESPONSE:\n%s\n", json_dumps(json_ret, JSON_INDENT(2)));
	
	for (i=0; i<num_objs; i++) {
		obj = json_array_get(json_ret, i);
		key = json_object_get(obj, "accessPoint");

		if (key)
			aps[i] = json_string_value(key);
	}


	*ret_aps = aps;

	/* do we free json_ret ?? */
	
	return 0;
}
