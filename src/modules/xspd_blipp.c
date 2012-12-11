#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "xsp_protocols.h"
#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_settings.h"
#include "xsp_main_settings.h"
#include "xsp_listener.h"
#include "xsp_session.h"
#include "xsp_conn.h"

#include "option_types.h"
#include "compat.h"

#include "mongo.h"

int xspd_blipp_init();
int xspd_blipp_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);
int __xspd_blipp_mongo_insert(bson *bpp, char *collection);

#define BLIPP_VERSION "0.1"

struct xspd_blipp_config_t {
	char *store;
	char *db_name;
	char *db_host;
	int   db_port;
	char *ms_instance;
	char *unis_instance;
};
		
struct xspd_blipp_config_t default_config = {
	.store = "mongo",
	.db_name = "xsp_blipp",
	.db_host = "localhost",
	.db_port = 27017,
	.ms_instance = NULL,
	.unis_instance = NULL
};

struct xspd_blipp_config_t config;

static xspModule xspd_blipp_module = {
	.desc = "BLIPP Module",
	.dependencies = "",
	.init = xspd_blipp_init,
	.opt_handler = xspd_blipp_opt_handler
};

xspModule *module_info() {
	return &xspd_blipp_module;
}

int xspd_blipp_init() {
	const xspSettings *settings;
	
	settings = xsp_main_settings();
	
	if (xsp_settings_get_2(settings, "blipp", "store", &config.store) != 0) {
		xsp_info(5, "No BLIPP store type specified, using default %s", default_config.store);
		config.store = default_config.store;
        }

        if (xsp_settings_get_2(settings, "blipp", "db_name", &config.db_name) != 0) {
		xsp_info(5, "BLIPP database name not specified, using default %s", default_config.db_name);
		config.db_name = default_config.db_name;
        }

	if (xsp_settings_get_2(settings, "blipp", "db_host", &config.db_host) != 0) {
                xsp_info(5, "BLIPP database host not specified, using default %s", default_config.db_host);
                config.db_host = default_config.db_host;
        }

	if (xsp_settings_get_int_2(settings, "blipp", "db_port", &config.db_port) != 0) {
                xsp_info(5, "BLIPP database port not specified, using default %d", default_config.db_port);
                config.db_port = default_config.db_port;
        }

	if (!strcmp(config.store, "periscope")) {
		if (xsp_settings_get_2(settings, "blipp", "ms_instance", &config.ms_instance) != 0) {
			xsp_info(5, "MS instance not specified!");
			return -1;
		}
		
		if (xsp_settings_get_2(settings, "blipp", "unis_instance", &config.unis_instance) != 0) {
			xsp_info(5, "UNIS instance not specified!");
			return -1;
		}

		/* persistent connection to UNIS/MS? */
	}
	else if (!strcmp(config.store, "mongo")) {
		/* persistent mongo conn?
		   we'll connect for each insert right now */
	}
	else {
		xsp_info(5, "Unrecognized BLIPP store type!");
		return -1;
	}

	return 0;
}

int xspd_blipp_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	xsp_info(11, "handling blipp message of type: %d", block->type);
	// block->blob has the data of length block->length

	bson b[1];
	char *bpp_data;
	
	bpp_data = (char *)malloc(block->length);
	memcpy(bpp_data, block->data, block->length);
	
	bson_init(b);
	bson_init_finished_data(b, bpp_data);
	bson_print(b);

	switch(block->type) {
		
	case BLIPP_BSON_DATA:
		{
			__xspd_blipp_mongo_insert(b, "data");
		}
		break;
	case BLIPP_BSON_META:
		{
			__xspd_blipp_mongo_insert(b, "meta");
		}
		break;
	default:
		break;
		
	}
	
	bson_destroy(b);
	*ret_block = NULL;

	return 0;
}

int __xspd_blipp_mongo_insert(bson *bpp, char *collection) {
	mongo conn[1];
	char *db_path = NULL;
	int status;

	status = mongo_client(conn, config.db_host, config.db_port);

	if( status != MONGO_OK ) {
		switch ( conn->err ) {
		case MONGO_CONN_NO_SOCKET:  fprintf(stderr, "no socket\n"); return -1;
		case MONGO_CONN_FAIL:       fprintf(stderr, "connection failed\n"); return -1;
		case MONGO_CONN_NOT_MASTER: fprintf(stderr, "not master\n"); return -1;
		default: return 1;
		}
	}

	asprintf(&db_path, "%s.%s", config.db_name, collection);
	status = mongo_insert(conn, db_path, bpp, NULL);
	if (status != MONGO_OK) {
		xsp_err(5, "Could not perform mongo insert");
		return -1;
	}
	mongo_destroy(conn);

	return 0;
}
