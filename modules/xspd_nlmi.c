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

#include "xspd_protocols.h"
#include "xspd_logger.h"
#include "xspd_config.h"
#include "xspd_tpool.h"
#include "xspd_modules.h"
#include "xspd_settings.h"
#include "xspd_listener.h"
#include "xspd_session.h"
#include "xspd_conn.h"

#include "option_types.h"
#include "compat.h"

#include "bson.h"

int xspd_nlmi_init();
int xspd_nlmi_opt_handler(xspdSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block);

static xspdModule xspd_nlmi_module = {
	.desc = "NLMI Module",
	.dependencies = "",
	.init = xspd_nlmi_init,
	.opt_handler = xspd_nlmi_opt_handler
};

xspdModule *module_info() {
	return &xspd_nlmi_module;
}

int xspd_nlmi_init() {
	
	// do any initialization code here
	
	return 0;

 error_exit:
	return -1;
}

int xspd_nlmi_opt_handler(xspdSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block) {

	xspd_info(0, "handling nlmi message of type: %d", block->type);
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
