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

#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_settings.h"
#include "xsp_session.h"
#include "xsp_conn.h"

#include "bson.h"
#include "option_types.h"
#include "compat.h"

int xspd_globus_xio_init();
int xspd_globus_xio_opt_handler(comSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block);

static xspModule xspd_globus_xio_module = {
	.desc = "Globus XIO Module",
	.dependencies = "",
	.init = xspd_globus_xio_init,
	.opt_handler = xspd_globus_xio_opt_handler
};

xspModule *module_info() {
	return &xspd_globus_xio_module;
}

int xspd_globus_xio_init() {
	
	// do any initialization code here
	
	return 0;

 error_exit:
	return -1;
}

int xspd_globus_xio_opt_handler(comSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block) {

	xsp_info(8, "handling globus_xio message of type: %d", block->type);
	// block->blob has the data of length block->length

	switch(block->type) {

	case GLOBUS_XIO_NEW_XFER:
		{
		    /*
		    char *tmp = malloc(block->length*sizeof(char)+1);
		    memcpy(tmp, block->blob, block->length);
		    tmp[block->length] = '\0';
		    xsp_info(10, "NEW XFER: %s\n", tmp);
		    free(tmp);
		    
		    *ret_block = (xspBlockHeader*)malloc(sizeof(xspBlockHeader));
		    (*ret_block)->blob = "This is my response";
		    (*ret_block)->length = strlen((*ret_block)->blob);
		    (*ret_block)->type = block->type;
		    (*ret_block)->sport = 0;
		    */

		    bson *bpp;
                    char *data;

                    data = (char *)malloc(block->length);
                    memcpy(data, block->blob, block->length);

                    bpp = (bson *)malloc(sizeof(bson));
                    bson_init(bpp, data, 1);

                    bson_print(bpp);

                    bson_destroy(bpp);
		    
		    *ret_block = NULL;
		}
		break;
	case GLOBUS_XIO_END_XFER:
	        {
		    /*
		    char *tmp = malloc(block->length*sizeof(char)+1);
		    memcpy(tmp, block->blob, block->length);
		    tmp[block->length] = '\0';
		    xsp_info(10, "END XFER: %s\n", tmp);
		    free(tmp);
		    */

		    bson *bpp;
                    char *data;

                    data = (char *)malloc(block->length);
                    memcpy(data, block->blob, block->length);

                    bpp = (bson *)malloc(sizeof(bson));
                    bson_init(bpp, data, 1);

                    bson_print(bpp);

                    bson_destroy(bpp);

		    *ret_block = NULL;
		}
		break;
	case GLOBUS_XIO_UPDATE_XFER:
	        {
		    /*
		    char *tmp = malloc(block->length*sizeof(char)+1);
		    memcpy(tmp, block->blob, block->length);
		    tmp[block->length] = '\0';
		    xsp_info(10, "NL UPDATE: %s\n", tmp);
		    free(tmp);
		    */

		    bson *bpp;
		    char *data;

		    data = (char *)malloc(block->length);
		    memcpy(data, block->blob, block->length);

		    bpp = (bson *)malloc(sizeof(bson));
		    bson_init(bpp, data, 1);
		    
		    bson_print(bpp);

		    bson_destroy(bpp);

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
