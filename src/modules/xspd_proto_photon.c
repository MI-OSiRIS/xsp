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

#include "xspd_proto_photon.h"
#include "xspd_forwarder.h"
#include "photon_xsp_forwarder.h"
#include "compat.h"

/* XXX: Is there a way to forward declare MPI_Aint and MPI_Datatype? */
#include <mpi.h>

int xspd_proto_photon_init();
int xspd_proto_photon_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);
xspBlock *__xspd_proto_photon_set_info(xspSess *sess, xspBlock *block, photon_info_t type);

static PhotonIOInfo *xspd_proto_photon_parse_io_msg(void *msg);

pthread_mutex_t ci_lock;
pthread_mutex_t rfi_lock;

static xspModule xspd_photon_module = {
	.desc = "Photon Control Module",
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

	MPI_Init(NULL, NULL);

	struct photon_config_t cfg = {
		.meta_exch = PHOTON_EXCH_MPI,
		.nproc = maxclients,
        .address = maxclients,
        .comm = MPI_COMM_WORLD,
        .use_forwarder = 1,
		.use_cma = 1,
        .eth_dev = "roce0",
        .ib_dev = "qib0",
		.ib_port = 1,
        .backend = "verbs"
	};

	if (photon_init(&cfg) != 0) {
		xsp_err(0, "could not init photon backend");
		goto error_exit;
	}

	pthread_mutex_init(&ci_lock, NULL);
	pthread_mutex_init(&rfi_lock, NULL);

	return 0;

error_exit:
	return -1;
}

int xspd_proto_photon_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

	xsp_info(0, "handling photon message of type: %d", block->type);

	switch(block->type) {

	case XSP_PHOTON_CI:
	{
		xspConn *parent_conn;
		/* XSP doesn't care what the photon connection context actually looks like,
		   but we need to know the length of the buffer to pass around */
		void *ci;
		void *ret_ci = NULL;
		int ci_len;
		int ret_len;

		parent_conn = LIST_FIRST(&sess->parent_conns);
		ci = block->data;
		ci_len = block->length;

		/* does not currently check for duplicate registrations
		   duplicate messages, etc. */
		if (photon_xsp_register_session((xspSess*)sess) != 0) {
			xsp_err(0, "could not register session with libphoton");
			goto error_exit;
		}

		if (photon_xsp_forwarder_connect_peer((xspSess*)sess, ci, &ret_ci, &ret_len) != PHOTON_OK) {
			xsp_err(0, "could not complete photon connections");
			goto error_conn;
		}

		*ret_block = xsp_alloc_block();
		(*ret_block)->data = ret_ci;
		(*ret_block)->length = ret_len;
		(*ret_block)->type = block->type;
		(*ret_block)->sport = 0;
		
		break;

error_conn:
		photon_xsp_unregister_session((xspSess*)sess);
		goto error_exit;
    }

	case XSP_PHOTON_RI:
	{
		*ret_block = __xspd_proto_photon_set_info((xspSess*)sess, block, PHOTON_RI);
		break;
    }

    case XSP_PHOTON_SI:
	{
		*ret_block = __xspd_proto_photon_set_info((xspSess*)sess, block, PHOTON_SI);
		break;
	}

	case XSP_PHOTON_FI:
	{
		*ret_block = __xspd_proto_photon_set_info((xspSess*)sess, block, PHOTON_FI);
		break;
	}

	case XSP_PHOTON_IO:
	{
		PhotonIOInfo *io = xspd_proto_photon_parse_io_msg(block->data);
		if(io == NULL)
			goto error_exit;

		__xspd_proto_photon_set_info((xspSess*)sess, block, PHOTON_IO);

		/*
		 * TODO: From here the phorwarder needs to start the I/O transfer
		 *   process. The following method is will block for io->niter RDMA
		 *   transfers. Does this method (opt_handler) need to return immediately?
		 *   What is the best way to run the I/O method? Create a new thread?
		 *   I think there is no problem with the session being unresponsive
		 *   until the I/O finishes.
		 */
		if (photon_xsp_do_io((xspSess*)sess) != 0) {
			xsp_err(0, "I/O processing failed");
			goto error_exit;
		}

		*ret_block = NULL;
		break;
	}

	default:
		xsp_err(0, "Uknown Photon message");
		break;
	}

	return 0;

error_exit:
	*ret_block = NULL;
	return -1;
}

xspBlock *__xspd_proto_photon_set_info(xspSess *sess, xspBlock *block, photon_info_t type) {
	xspBlock *ret_block;
	void *ri;
	void *ret_ri;
	int ri_len;
	int ret_len;
	
	ri = block->data;
	ri_len = block->length;
	
	if (photon_xsp_set_info((xspSess*)sess, ri, ri_len, &ret_ri, &ret_len, type) != PHOTON_OK) {
		xsp_err(0, "could not set photon rcv ledgers");
		return NULL;
	}
	
	ret_block = xsp_alloc_block();
	ret_block->data = ret_ri;
	ret_block->length = sizeof(void);
	ret_block->type = block->type;
	ret_block->sport = 0;	
	
	return ret_block;
}

int xspd_proto_photon_register_buffer(void *buf, uint64_t size, photonBufferPriv ret_priv) {
	if (photon_register_buffer(buf, size) != PHOTON_OK) {
		return -1;
	}
	if (ret_priv && (photon_get_buffer_private(buf, size, ret_priv) != PHOTON_OK)) {
		return -1;
	}
	
	return 0;
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
        xsp_err(0, "xspd_proto_photon_parse_io_msg: out of memory");
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

	photon_io_print_info(io);

	return NULL;

    return io;
}
