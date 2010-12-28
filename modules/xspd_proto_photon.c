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

#include "photon.h"

#include "option_types.h"
#include "compat.h"

int xspd_proto_photon_init();
int xspd_proto_photon_opt_handler(xspBlockHeader *block, xspBlockHeader **ret_block);

static xspdConn *xspd_proto_photon_connect(const char *hop_id, xspdSettings *settings);
static xspdListener *xspd_proto_photon_setup_listener(const char *listener_id, xspdSettings *settings, int one_shot, listener_cb callback, void *arg);

// maybe we eventually want this to be a generic protocal handler
static xspdProtocolHandler xspd_photon_handler = {
	.connect = xspd_proto_photon_connect,
	.setup_listener = xspd_proto_photon_setup_listener,
	.name = "photon"
};

static xspdModule xspd_photon_module = {
	.desc = "Photon Forwarder Module",
	.dependencies = "",
	.init = xspd_proto_photon_init,
	.opt_handler = xspd_proto_photon_opt_handler
};

xspdModule *module_info() {
	return &xspd_photon_module;
}

int xspd_proto_photon_init() {
	
	// maybe we eventually want this to be a generic protocal handler
	//if (xspd_add_protocol_handler(&xspd_photon_handler)) {
	//      xspd_err(0, "couldn't add protocol handler");
	//	goto error_exit;
	//}

	return 0;
}

int xspd_proto_photon_opt_handler(xspBlockHeader *block, xspBlockHeader **ret_block) {

	xspd_info(0, "handling photon message!: %s", (char*)block->blob);

	*ret_block = (xspBlockHeader*)malloc(sizeof(xspBlockHeader));
	(*ret_block)->blob = "blah";
	(*ret_block)->length = 6;
	(*ret_block)->type = PHOTON_DAPL;
	(*ret_block)->sport = 0;

	return 0;
}

static xspdConn *xspd_proto_photon_connect(const char *hostname, xspdSettings *settings) {
	// we're not connecting with photon from here, yet

	return NULL;
}

static xspdListener *xspd_proto_photon_setup_listener(const char *listener_id, xspdSettings *settings, int one_shot, listener_cb callback, void *arg) {
	
	return NULL;
}
