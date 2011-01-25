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

#include "xspd_logger.h"
#include "xspd_config.h"
#include "xspd_tpool.h"
#include "xspd_modules.h"
#include "xspd_settings.h"
#include "xspd_session.h"
#include "xspd_conn.h"

#include "option_types.h"
#include "compat.h"

int xspd_globus_xio_init();
int xspd_globus_xio_opt_handler(xspdSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block);

static xspdModule xspd_globus_xio_module = {
	.desc = "Globus XIO Module",
	.dependencies = "",
	.init = xspd_globus_xio_init,
	.opt_handler = xspd_globus_xio_opt_handler
};

xspdModule *module_info() {
	return &xspd_globus_xio_module;
}

int xspd_globus_xio_init() {
	
	// do any initialization code here
	
	return 0;

 error_exit:
	return -1;
}

int xspd_globus_xio_opt_handler(xspdSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block) {

	xspd_info(0, "handling globus_xio message of type: %d", block->type);
	// block->blob has the data of length block->length

	switch(block->type) {

	case GLOBUS_XIO_NEW_XFER:
		{
		    char *tmp = malloc(block->length*sizeof(char));
		    memcpy(tmp, block->blob, block->length);
		    tmp[block->length] = '\0';
		    xspd_info(0, "NEW XFER: %s\n", tmp);
		    free(tmp);
		    
		    //*ret_block = (xspBlockHeader*)malloc(sizeof(xspBlockHeader));
		    //(*ret_block)->blob = "This is my response";
		    //(*ret_block)->length = strlen((*ret_block)->blob);
		    //(*ret_block)->type = block->type;
		    //(*ret_block)->sport = 0;
		    *ret_block = NULL;
		}
		break;
	case GLOBUS_XIO_END_XFER:
	        {
		    char *tmp = malloc(block->length*sizeof(char));
		    memcpy(tmp, block->blob, block->length);
		    tmp[block->length] = '\0';
		    xspd_info(0, "END XFER: %s\n", tmp);
		    free(tmp);
		    *ret_block = NULL;
		}
		break;
	case GLOBUS_XIO_UPDATE_XFER:
		{
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
