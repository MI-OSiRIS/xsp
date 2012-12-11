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
#include "xsp_listener.h"
#include "xsp_session.h"
#include "xsp_conn.h"

#include "hashtable.h"
#include "hashtable_util.h"

#include "option_types.h"
#include "compat.h"

#include "bson.h"

int xspd_blipp_init();
int xspd_blipp_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);

#define BLIPP_VERSION "0.1"

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
	
	return 0;
}

int xspd_blipp_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	xsp_info(0, "handling blipp message of type: %d", block->type);
	// block->blob has the data of length block->length

	switch(block->type) {
		
	case BLIPP_BSON_DATA:
	case BLIPP_BSON_META:
		{
			bson b[1];
			char *bpp_data;
			
			bpp_data = (char *)malloc(block->length);
			memcpy(bpp_data, block->data, block->length);
			
			bson_init(b);
			bson_init_finished_data(b, bpp_data);
			bson_print(b);
			bson_destroy(b);
			
			*ret_block = NULL;
		}
		break;
	default:
		break;
		
	}
	
	return 0;
}
