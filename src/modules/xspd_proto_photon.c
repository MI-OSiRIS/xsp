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
#include "xsp_main_settings.h"
#include "xsp_settings.h"
#include "xsp_listener.h"
#include "xsp_session.h"
#include "xsp_conn.h"

#include "photon_xsp.h"
#include "compat.h"

/* XXX: Is there a way to forward declare MPI_Aint and MPI_Datatype? */
#include <mpi.h>

// FIXME: XSP shouldn't know internals of Photon; right now this is a mess.
#define MAX_QP 1
typedef struct gen2_cnct_info {
    int lid;
    int qpn;
    int psn;
} gen2_cnct_info_t;

///////////////////
// phorwarder libphoton util
int gen2_xsp_register_session(xspSess *sess);
int gen2_xsp_unregister_session(xspSess *sess);
int gen2_xsp_get_local_ci(xspSess *sess, gen2_cnct_info_t **ci);
int gen2_xsp_server_connect_peer(xspSess *sess, gen2_cnct_info_t *local_ci, gen2_cnct_info_t *remote_ci);
int gen2_xsp_set_ri(xspSess *sess, PhotonLedgerInfo *ri, PhotonLedgerInfo **ret_ri);
int gen2_xsp_set_si(xspSess *sess, PhotonLedgerInfo *si, PhotonLedgerInfo **ret_si);
int gen2_xsp_set_fi(xspSess *sess, PhotonLedgerInfo *fi, PhotonLedgerInfo **ret_fi);
int gen2_xsp_set_io(xspSess *sess, PhotonIOInfo *io);

int gen2_xsp_do_io(xspSess *sess);
void print_photon_io_info(PhotonIOInfo *io);

int xspd_proto_photon_init();
int xspd_proto_photon_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);

static PhotonIOInfo *xspd_proto_photon_parse_io_msg(void *msg);

pthread_mutex_t ci_lock;
pthread_mutex_t rfi_lock;

static xspModule xspd_photon_module = {
	.desc = "Photon Forwarder Module",
	.dependencies = "",
	.init = xspd_proto_photon_init,
	.opt_handler = xspd_proto_photon_opt_handler
};


xspModule *module_info() {
	return &xspd_photon_module;
}

int xspd_proto_photon_init() {
	int maxclients;
	xspSettings *settings;

	if (xsp_main_settings_get_section("photon", &settings) != 0 ||
			xsp_settings_get_int(settings, "maxclients", &maxclients) != 0) {
		maxclients = 46; /* default */
	}

	if (photon_xsp_init_server(maxclients) != 0) {
		xsp_err(0, "could not init photon backend");
		goto error_exit;
	}

	pthread_mutex_init(&ci_lock, NULL);
	pthread_mutex_init(&rfi_lock, NULL);

	return 0;

error_exit:
	return -1;
}

int xsp_proto_photon_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	xsp_info(0, "handling photon message of type: %d", block->type);

	switch(block->type) {

	case PHOTON_CI:
	{
		xspConn *parent_conn;
		gen2_cnct_info_t *ci;
		gen2_cnct_info_t *ret_ci;

		parent_conn = LIST_FIRST(&sess->parent_conns);
		ci = (gen2_cnct_info_t*) block->data;

		// does not currently check for duplicate registrations
		// duplicate messages, etc.
		if (gen2_xsp_register_session((xspSess*)sess) != 0) {
			xsp_err(0, "could not register session with libphoton");
			goto error_exit;
		}

		if (gen2_xsp_get_local_ci((xspSess*)sess, &ret_ci) != 0) {
			xsp_err(0, "could not set photon connect info");
			goto error_ci;
		}

		*ret_block = xsp_alloc_block();
		(*ret_block)->data = ret_ci;
		(*ret_block)->length = sizeof(gen2_cnct_info_t);
		(*ret_block)->type = block->type;
		(*ret_block)->sport = 0;

		// so ugly to do this here
		xsp_conn_send_msg(parent_conn, XSP_MSG_APP_DATA, *ret_block);

		// but it's better to wait for the ib connection right away
		if (gen2_xsp_server_connect_peer((xspSess*)sess, ret_ci, ci) != 0) {
			xsp_err(0, "could not complete IB qp connections");
			goto error_qps;
		}

		free(ret_ci);

		// we already sent our PHOTON_CI message back
		*ret_block = NULL;

		break;

error_qps:
		free(ret_ci);
error_ci:
		gen2_xsp_unregister_session((xspSess*)sess);
		goto error_exit;
    }

	case PHOTON_RI:
	{
		PhotonLedgerInfo *ri;
		PhotonLedgerInfo *ret_ri;

		ri = (PhotonLedgerInfo*) block->data;

		if (gen2_xsp_set_ri((xspSess*)sess, ri, &ret_ri) != 0) {
			xsp_err(0, "could not set photon rcv ledgers");
			goto error_exit;
		}

		*ret_block = xsp_alloc_block();
		(*ret_block)->data = ret_ri;
		(*ret_block)->length = sizeof(PhotonLedgerInfo);
		(*ret_block)->type = block->type;
		(*ret_block)->sport = 0;

		break;
    }

    case PHOTON_SI:
	{
		PhotonLedgerInfo *si;
		PhotonLedgerInfo *ret_si;

		si = (PhotonLedgerInfo*) block->data;

		if (gen2_xsp_set_si((xspSess*)sess, si, &ret_si) != 0) {
			xsp_err(0, "could not set photon snd ledgers");
			goto error_exit;
		}

		*ret_block = xsp_alloc_block();
		(*ret_block)->data = ret_si;
		(*ret_block)->length = sizeof(PhotonLedgerInfo);
		(*ret_block)->type = block->type;
		(*ret_block)->sport = 0;

		break;
	}

	case PHOTON_FI:
	{
		PhotonLedgerInfo *fi;
		PhotonLedgerInfo *ret_fi;

		fi = (PhotonLedgerInfo*) block->data;

		if (gen2_xsp_set_fi((xspSess*)sess, fi, &ret_fi) != 0) {
			xsp_err(0, "could not set photon FIN ledgers");
			goto error_exit;
		}

		// FIXME: There's a memory leak because blob is not freed
		*ret_block = xsp_alloc_block();
		(*ret_block)->data = ret_fi;
		(*ret_block)->length = sizeof(PhotonLedgerInfo);
		(*ret_block)->type = block->type;
		(*ret_block)->sport = 0;

		break;
	}

	case PHOTON_IO:
	{
		PhotonIOInfo *io = xspd_proto_photon_parse_io_msg(block->data);
		if(io == NULL)
			goto error_exit;

		/* XXX: AFAIK the I/O info is session specific, so no need for locks */
		if (gen2_xsp_set_io((xspSess*)sess, io) != 0) {
			xsp_err(0, "could not set photon I/O info");
			goto error_exit;
		}

		/*
		 * TODO: From here the phorwarder needs to start the I/O transfer
		 *   process. The following method is will block for io->niter RDMA
		 *   transfers. Does this method (opt_handler) need to return immediately?
		 *   What is the best way to run the I/O method? Create a new thread?
		 *   I think there is no problem with the session being unresponsive
		 *   until the I/O finishes.
		 */
		if (gen2_xsp_do_io((xspSess*)sess) != 0) {
			xsp_err(0, "I/O processing failed");
			goto error_exit;
		}

		*ret_block = NULL;
		break;
	}

	default:
		break;
	}

	return 0;

error_exit:
	*ret_block = NULL;
	return -1;
}

PhotonIOInfo *xspd_proto_photon_parse_io_msg(void *msg) {
    int fileURI_size;
    PhotonIOInfo *io = malloc(sizeof(PhotonIOInfo));
    void *msg_ptr = msg;

    /* TODO: Assumes block->data will be freed by xspd. True? */
    fileURI_size = *((int *)msg);
    io->fileURI = strdup((char*)(msg+sizeof(int)));
    if (fileURI_size != strlen(io->fileURI) + 1) {
        xsp_err(0, "xspd_proto_photon_parse_io_msg: fileURI size mismatch");
        return NULL;
    }
    msg_ptr = msg + sizeof(int) + fileURI_size;

    io->amode = *((int *)msg_ptr);
    io->niter = *((int *)(msg_ptr+sizeof(int)));
    io->view.combiner = *((int *)(msg_ptr+sizeof(int)*2));
    msg_ptr += sizeof(int)*3;

    io->view.nints = *((int *)msg_ptr);
    io->view.integers = malloc(io->view.nints*sizeof(int));
    if(io->view.integers == NULL) {
        xspd_err(0, "xspd_proto_photon_parse_io_msg: out of memory");
        return NULL;
    }
    memcpy(io->view.integers, msg_ptr+sizeof(int), io->view.nints*sizeof(int));
    msg_ptr += sizeof(int) + io->view.nints*sizeof(int);

    io->view.naddrs = *((int *)msg_ptr);
    io->view.addresses = malloc(io->view.naddrs*sizeof(MPI_Aint));
    if(io->view.addresses == NULL) {
        xsp_err(0, "xspd_proto_photon_parse_io_msg: out of memory");
        return NULL;
    }
    memcpy(io->view.addresses, msg_ptr+sizeof(int), io->view.naddrs*sizeof(MPI_Aint));
    msg_ptr += sizeof(int) + io->view.naddrs*sizeof(MPI_Aint);

    io->view.ndatatypes = *((int *)msg_ptr);
    io->view.datatypes = malloc(io->view.ndatatypes*sizeof(int));
    if(io->view.datatypes == NULL) {
        xsp_err(0, "xspd_proto_photon_parse_io_msg: out of memory");
        return NULL;
    }
    memcpy(io->view.datatypes, msg_ptr+sizeof(int), io->view.ndatatypes*sizeof(int));

    print_photon_io_info(io);

    return io;
}
