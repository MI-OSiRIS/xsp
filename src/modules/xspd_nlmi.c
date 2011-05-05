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

#include "option_types.h"
#include "compat.h"

#include "bson.h"

int xspd_nlmi_init();
int xspd_nlmi_opt_handler(comSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block);

static xspModule xspd_nlmi_module = {
	.desc = "NLMI Module",
	.dependencies = "",
	.init = xspd_nlmi_init,
	.opt_handler = xspd_nlmi_opt_handler
};

xspModule *module_info() {
	return &xspd_nlmi_module;
}

int xspd_nlmi_init() {
	
	// do any initialization code here
	
	return 0;

 error_exit:
	return -1;
}

int xspd_nlmi_opt_handler(comSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block) {

	xsp_info(0, "handling nlmi message of type: %d", block->type);
	// block->blob has the data of length block->length

	switch(block->type) {

	case NLMI_BSON:
		{
			bson *bpp;
			char *data;
			
			data = (char *)malloc(block->length);
			memcpy(data, block->blob, block->length);

			bpp = (bson *)malloc(sizeof(bson));
			bson_init(bpp, data, 1);
			
			bson_print(bpp);

			// fill in an option block to return
			*ret_block = NULL;
		}
		break;
	default:
		break;
		
	}
	
	return 0;

 error_exit:
	*ret_block = NULL;
	return -1;
}
