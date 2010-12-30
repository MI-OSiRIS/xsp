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

#include "photon.h"

#include "option_types.h"
#include "compat.h"

///////////////////
// phorwarder libphoton util
int dapl_xsp_register_session(xspSess *sess);
int dapl_xsp_unregister_session(xspSess *sess);
int dapl_xsp_wait_connect(xspSess *sess);
int dapl_xsp_get_ci(xspSess *sess, PhotonConnectInfo *ci);
int dapl_xsp_set_ci(xspSess *sess, PhotonConnectInfo *ci, PhotonConnectInfo **ret_ci);
int dapl_xsp_get_ri(xspSess *sess, PhotonRIInfo *ri);
int dapl_xsp_set_ri(xspSess *sess, PhotonRIInfo *ri, PhotonRIInfo **ret_ri);
int dapl_xsp_get_fi(xspSess *sess, PhotonFINInfo *fi);
int dapl_xsp_set_fi(xspSess *sess, PhotonFINInfo *fi, PhotonFINInfo **ret_fi);

int dapl_xsp_post_recv(xspSess* sess, char *ptr, uint32_t size, uint32_t *request);
int dapl_xsp_post_send(xspSess* sess, char *ptr, uint32_t size, uint32_t *request);
int dapl_xsp_post_recv_buffer_rdma(xspSess* sess, char *ptr, uint32_t size, int tag, uint32_t *request);
int dapl_xsp_post_send_buffer_rdma(xspSess* sess, char *ptr, uint32_t size, int tag, uint32_t *request);
int dapl_xsp_post_send_request_rdma(xspSess* sess, uint32_t size, int tag, uint32_t *request);
int dapl_xsp_wait_recv_buffer_rdma(xspSess* sess, int tag);
int dapl_xsp_post_os_put(xspSess* sess, char *ptr, uint32_t size, int tag, uint32_t remote_offset, uint32_t *request);
int dapl_xsp_post_os_get(xspSess *sess, char *ptr, uint32_t size, int tag, uint32_t remote_offset, uint32_t *request);

int xspd_proto_photon_init();
int xspd_proto_photon_opt_handler(xspdSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block);

static xspdConn *xspd_proto_photon_connect(const char *hop_id, xspdSettings *settings);
static xspdListener *xspd_proto_photon_setup_listener(const char *listener_id, xspdSettings *settings, int one_shot, listener_cb callback, void *arg);

pthread_mutex_t ci_lock;

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

	// allow 4 libphoton client connections to test
	if (photon_xsp_init_server(4) != 0) {
		xspd_err(0, "could not init photon backend");
		goto error_exit;
	}

	pthread_mutex_init(&ci_lock, NULL);

	return 0;

 error_exit:
	return -1;
}

int xspd_proto_photon_opt_handler(xspdSess *sess, xspBlockHeader *block, xspBlockHeader **ret_block) {

	xspd_info(0, "handling photon message of type: %d", block->type);

	switch(block->type) {

	case PHOTON_CI:
		{
			xspdConn *parent_conn;
			PhotonConnectInfo *ci;
			PhotonConnectInfo *ret_ci = malloc(sizeof(PhotonConnectInfo));
			
			parent_conn = LIST_FIRST(&sess->parent_conns);

			ci = (PhotonConnectInfo*) block->blob;
			
			// does not currently check for duplicate registrations
			// duplicate messages, etc.
			if (dapl_xsp_register_session((xspSess*)sess) != 0) {
				xspd_err(0, "could not register session with libphoton");
				goto error_exit;
			}
			
			pthread_mutex_lock(&ci_lock);
			{
				if (dapl_xsp_set_ci((xspSess*)sess, ci, &ret_ci) != 0) {
					xspd_err(0, "could not set photon connect info");
					goto error_exit;
				}
			}
			pthread_mutex_unlock(&ci_lock);

			*ret_block = (xspBlockHeader*)malloc(sizeof(xspBlockHeader));
			(*ret_block)->blob = ret_ci;
			(*ret_block)->length = sizeof(PhotonConnectInfo);
			(*ret_block)->type = block->type;
			(*ret_block)->sport = 0;
			
			// so ugly to do this here
			xspd_conn_send_msg(parent_conn, XSP_MSG_APP_DATA, *ret_block);
			
			// but it's better to wait for the dapl connection right away
			if (dapl_xsp_wait_connect((xspSess*)sess) != 0) {
				xspd_err(0, "could not complete dapl connections");
				goto error_exit;
			}
			// we already sent our PHOTON_CI message back
			*ret_block = NULL;
		}
		break;
	case PHOTON_RI:
		{
			PhotonRIInfo *ri;
                        PhotonRIInfo *ret_ri = malloc(sizeof(PhotonRIInfo));
			
			ri = (PhotonRIInfo*) block->blob;

			if (dapl_xsp_set_ri((xspSess*)sess, ri, &ret_ri) != 0) {
				xspd_err(0, "could not set photon snd/rcv ledgers");
				goto error_exit;
			}
			
			*ret_block = (xspBlockHeader*)malloc(sizeof(xspBlockHeader));
                        (*ret_block)->blob = ret_ri;
                        (*ret_block)->length = sizeof(PhotonRIInfo);
                        (*ret_block)->type = block->type;
                        (*ret_block)->sport = 0;
		}
		break;
	case PHOTON_FI:
		{
			PhotonFINInfo *fi;
                        PhotonFINInfo *ret_fi = malloc(sizeof(PhotonFINInfo));

                        fi = (PhotonFINInfo*) block->blob;

                        if (dapl_xsp_set_fi((xspSess*)sess, fi, &ret_fi) != 0) {
                                xspd_err(0, "could not set photon FIN ledger");
                                goto error_exit;
                        }

                        *ret_block = (xspBlockHeader*)malloc(sizeof(xspBlockHeader));
                        (*ret_block)->blob = ret_fi;
                        (*ret_block)->length = sizeof(PhotonFINInfo);
                        (*ret_block)->type = block->type;
                        (*ret_block)->sport = 0;
		}
		break;
	case PHOTON_IO:
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

static xspdConn *xspd_proto_photon_connect(const char *hostname, xspdSettings *settings) {
	// we're not connecting with photon from here, yet

	return NULL;
}

static xspdListener *xspd_proto_photon_setup_listener(const char *listener_id, xspdSettings *settings, int one_shot, listener_cb callback, void *arg) {
	
	return NULL;
}
