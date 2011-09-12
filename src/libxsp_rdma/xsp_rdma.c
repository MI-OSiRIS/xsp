#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <time.h>
#include <errno.h>

#include "xsp_rdma.h"

static int sl = 0;
static int page_size;
static pid_t pid;

static struct xfer_context *__xsp_rdma_init_ctx(void *, struct xfer_data *);
static int __xsp_rdma_poll_cq(struct xfer_context *ctx, struct ibv_wc *ret_wc, int sleep);
static int __xsp_rdma_post_recv(struct xfer_context *ctx);
static int __xsp_rdma_send_msg(struct xfer_context *ctx, int poll_cq);
static int __xsp_rdma_do_rdma(struct xsp_rdma_buf_handle_t *handle);

static int __xsp_rdma_poll_cq(struct xfer_context *ctx, struct ibv_wc *ret_wc, int sleep)
{
	//void *ctx_ptr;
	int ne;

	/*
	if (ibv_get_cq_event(ctx->ch, &ctx->cq, &ctx_ptr)) {
		fprintf(stderr, "Failed to get cq_event\n");
		return -1;
	}
	
	ibv_ack_cq_events(ctx->cq, 1);

	if (ibv_req_notify_cq(ctx->cq, 0)) {
		fprintf(stderr, "Couldn't request CQ notification\n");
		return -1;
	}
	*/
	
	do {
		if (sleep)
			usleep(100);
		ne = ibv_poll_cq(ctx->cq, 1, ret_wc);
		if (ne < 0) {
			fprintf(stderr, "Failed to poll completions from the CQ\n");
			return -1;
		}
	} while (ne == 0);
	
	if (ret_wc->status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Completion with status 0x%x was found\n", ret_wc->status);
		return -1;
	}
	
	return 0;
}

static int __xsp_rdma_post_recv(struct xfer_context *ctx)
{
        struct ibv_sge list;
        struct ibv_recv_wr wr, *bad_wr;
        int rc;

	memset(&wr, 0, sizeof(wr));

        list.addr = (uintptr_t) ctx->recv_msg;
        list.length = sizeof(struct message);
        list.lkey = ctx->recv_mr->lkey;
        wr.next = NULL;
        wr.wr_id = 0xcafebabe;
        wr.sg_list = &list;
        wr.num_sge = 1;

        rc = ibv_post_recv(ctx->qp, &wr, &bad_wr);
        if (rc) {
                perror("ibv_post_recv");
                fprintf(stderr, "%d:%s: ibv_post_recv failed %d\n", pid,
			__func__, rc);
		return -1;
        }
	
	return 0;
}

static int __xsp_rdma_do_rdma(struct xsp_rdma_buf_handle_t *handle)
{
	struct xfer_context *ctx = handle->ctx;
        struct ibv_send_wr *bad_wr;

	ctx->list.addr = (uintptr_t) handle->buf;
	ctx->list.length = handle->size;
	ctx->list.lkey = handle->local_mr->lkey;

        ctx->wr.wr.rdma.remote_addr = (uintptr_t) handle->remote_mr->addr;
        ctx->wr.wr.rdma.rkey = handle->remote_mr->rkey;
        ctx->wr.wr_id      = handle->id;
	ctx->wr.sg_list    = &ctx->list;
	ctx->wr.num_sge    = 1;
	ctx->wr.opcode     = handle->opcode;
        ctx->wr.send_flags = IBV_SEND_SIGNALED;
	ctx->wr.next       = NULL;
	
        if (ibv_post_send(ctx->qp, &ctx->wr, &bad_wr)) {
                fprintf(stderr, "%d:%s: ibv_post_send failed\n", pid, __func__);
		perror("ibv_post_send");
                return -1;
        }

	return 0;
}

static int __xsp_rdma_send_msg(struct xfer_context *ctx, int poll_cq)
{
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	struct ibv_wc wc;

	memset(&wr, 0, sizeof(wr));

	sge.addr = (uintptr_t) ctx->send_msg;
	sge.length = sizeof(struct message);
	sge.lkey = ctx->send_mr->lkey;

	wr.wr_id = 0xabbaabba;
	wr.opcode = IBV_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.next = NULL;

        if (ibv_post_send(ctx->qp, &wr, &bad_wr)) {
                fprintf(stderr, "%d:%s: ibv_post_send failed\n", pid, __func__);
                perror("ibv_post_send");
                return -1;
        }

	if (poll_cq) {
		__xsp_rdma_poll_cq(ctx, &wc, 0);
		
		if (wc.opcode != IBV_WC_SEND)
			fprintf(stderr, "%d:%s: bad wc opcode %d\n", pid, __func__,
				wc.opcode);
		if (wc.wr_id != 0xabbaabba)
			fprintf(stderr, "%d:%s: bad wc wr_id 0x%x\n", pid, __func__,
				(int)wc.wr_id);
	}

	return 0;
}

static struct xfer_context *__xsp_rdma_init_ctx(void *ptr, struct xfer_data *data)
{
        struct xfer_context *ctx;
        struct rdma_cm_id *cm_id = NULL;

        ctx = malloc(sizeof *ctx);
        if (!ctx)
                return NULL;

        ctx->tx_depth = data->tx_depth;
        
        if (data->use_cma) {
                cm_id = (struct rdma_cm_id *)ptr;
                ctx->context = cm_id->verbs;
                if (!ctx->context) {
                        fprintf(stderr, "%d:%s: Unbound cm_id!!\n", pid,
				__func__);
                        return NULL;
                }

        } else {
		// use alternative to CMA here
        }

        ctx->pd = ibv_alloc_pd(ctx->context);
        if (!ctx->pd) {
                fprintf(stderr, "%d:%s: Couldn't allocate PD\n", pid, __func__);
                return NULL;
        }

	// setup the message buffers
	ctx->send_msg = malloc(sizeof(struct message));
	ctx->recv_msg = malloc(sizeof(struct message));

	ctx->recv_mr = ibv_reg_mr(ctx->pd, ctx->recv_msg, sizeof(struct message),
				  IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);
	if (!ctx->recv_mr) {
		fprintf(stderr, "%d:%s: Couldn't allocate MR\n", pid, __func__);
		return NULL;
	}
	
	ctx->send_mr = ibv_reg_mr(ctx->pd, ctx->send_msg, sizeof(struct message),
				  IBV_ACCESS_LOCAL_WRITE);
        if (!ctx->send_mr) {
                fprintf(stderr, "%d:%s: Couldn't allocate MR\n", pid, __func__);
                return NULL;
        }

        ctx->ch = ibv_create_comp_channel(ctx->context);
        if (!ctx->ch) {
                fprintf(stderr, "%d:%s: Couldn't create comp channel\n", pid,
			__func__);
                return NULL;
        }

	ctx->cq = ibv_create_cq(ctx->context, ctx->tx_depth+1, ctx, ctx->ch, 0);
        if (!ctx->cq) {
                fprintf(stderr, "%d:%s: Couldn't create CQ\n", pid, __func__);
                return NULL;
        }

	if (ibv_req_notify_cq(ctx->cq, 0)) {
		fprintf(stderr, "%d:%s: Couldn't request CQ notification\n", 
			pid, __func__);
		return NULL;
	}

        struct ibv_qp_init_attr attr = {
                .send_cq = ctx->cq,
                .recv_cq = ctx->cq,
                .cap     = {
                        .max_send_wr  = ctx->tx_depth+1,
                        .max_recv_wr  = ctx->tx_depth+1,
                        .max_send_sge = 1,
                        .max_recv_sge = 1,
                        .max_inline_data = 0
                },
                .qp_type = IBV_QPT_RC
        };

	if (data->use_cma) {
                if (rdma_create_qp(cm_id, ctx->pd, &attr)) {
                        fprintf(stderr, "%d:%s: Couldn't create QP\n", pid, __func__);
                        return NULL;
                }
                ctx->qp = cm_id->qp;
		// arm the QP
		__xsp_rdma_post_recv(ctx);
                return ctx;
        } else {
		// use an alternative to CMA here
		ctx = NULL;
		return ctx;
	}
}

struct xfer_context *xsp_rdma_client_connect(struct xfer_data *data)
{
	struct addrinfo *res;
	struct addrinfo hints = {
                .ai_family   = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM
	};
	
	char *service;
	int n;
	int n_retries = 10;
	struct rdma_cm_event *event;
	struct sockaddr_in sin;
	struct xfer_context *ctx = NULL;
	struct rdma_conn_param conn_param;
	
	if (asprintf(&service, "%d", data->port) < 0)
		goto err4;
	
	n = getaddrinfo(data->servername, service, &hints, &res);
	
	if (n < 0) {
		fprintf(stderr, "%d:%s: %s for %s:%d\n",
			pid, __func__, gai_strerror(n),
			data->servername, data->port);
		goto err4;
	}
	
	if (data->use_cma) {
		sin.sin_addr.s_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(data->port);

	retry_addr:
		if (rdma_resolve_addr(data->cm_id, NULL,
				      (struct sockaddr *)&sin, 2000)) {
			fprintf(stderr, "%d:%s: rdma_resolve_addr failed\n",
				pid, __func__ );
			goto err2;
		}
		
		if (rdma_get_cm_event(data->cm_channel, &event))
			goto err2;
		
		if (event->event == RDMA_CM_EVENT_ADDR_ERROR
		    && n_retries-- > 0) {
			rdma_ack_cm_event (event);
			goto retry_addr;
		}
		
		if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED) {
			fprintf(stderr, "%d:%s: unexpected CM event %d\n",
				pid, __func__, event->event);
			goto err1;
		}
		rdma_ack_cm_event(event);
		
	retry_route:
		if (rdma_resolve_route(data->cm_id, 2000)) {
			fprintf(stderr, "%d:%s: rdma_resolve_route failed\n",
				pid, __func__);
			goto err2;
		}
		
		if (rdma_get_cm_event(data->cm_channel, &event))
			goto err2;
		
		if (event->event == RDMA_CM_EVENT_ROUTE_ERROR
		    && n_retries-- > 0) {
			rdma_ack_cm_event(event);
			goto retry_route;
		}
		
		if (event->event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
			fprintf(stderr, "%d:%s: unexpected CM event %d\n",
				pid, __func__, event->event);
			rdma_ack_cm_event(event);
			goto err2;
		}
		rdma_ack_cm_event(event);
		ctx = __xsp_rdma_init_ctx(data->cm_id, data);
		if (!ctx) {
			fprintf(stderr, "%d:%s: xfer_init_ctx failed\n", pid, __func__);
			goto err2;
		}

		memset(&conn_param, 0, sizeof conn_param);
		conn_param.responder_resources = 1;
		conn_param.initiator_depth = 1;
		conn_param.retry_count = 5;
		conn_param.private_data = NULL;
		conn_param.private_data_len = 0;
		
		if (rdma_connect(data->cm_id, &conn_param)) {
			fprintf(stderr, "%d:%s: rdma_connect failure\n", pid, __func__);
			goto err2;
		}
		
		if (rdma_get_cm_event(data->cm_channel, &event))
			goto err2;
		
		if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
			fprintf(stderr, "%d:%s: unexpected CM event %d\n",
				pid, __func__, event->event);
			goto err1;
		}
		rdma_ack_cm_event(event);		
	} else {
		// use an alternative to CMA here
	}

	freeaddrinfo(res);
        return ctx;
	
 err1:
        rdma_ack_cm_event(event);
 err2:
        rdma_destroy_id(data->cm_id);
        rdma_destroy_event_channel(data->cm_channel);
 err4:
        return NULL;

}

struct xfer_context *xsp_rdma_server_connect(struct xfer_data *data)
{
        struct addrinfo *res;
        struct addrinfo hints = {
                .ai_flags    = AI_PASSIVE,
                .ai_family   = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM
        };
        char *service;
        int n;
        struct rdma_cm_event *event;
        struct sockaddr_in sin;
        struct xfer_context *ctx = NULL;
        struct rdma_cm_id *child_cm_id;
        struct rdma_conn_param conn_param;

        if (asprintf(&service, "%d", data->port) < 0)
                goto err5;

        if ( (n = getaddrinfo(NULL, service, &hints, &res)) < 0 ) {
                fprintf(stderr, "%d:%s: %s for port %d\n", pid, __func__,
			gai_strerror(n), data->port);
                goto err5;
        }
	
	if (data->use_cma) {
                sin.sin_addr.s_addr = 0;
                sin.sin_family = AF_INET;
                sin.sin_port = htons(data->port);
                if (rdma_bind_addr(data->cm_id, (struct sockaddr *)&sin)) {
                        fprintf(stderr, "%d:%s: rdma_bind_addr failed\n", pid, __func__);
                        goto err3;
                }

                if (rdma_listen(data->cm_id, 0)) {
                        fprintf(stderr, "%d:%s: rdma_listen failed\n", pid, __func__);
                        goto err3;
                }

                if (rdma_get_cm_event(data->cm_channel, &event))
                        goto err3;

                if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
                        fprintf(stderr, "%d:%s: bad event waiting for connect request %d\n",
                                pid, __func__, event->event);
                        goto err2;
                }

                child_cm_id = (struct rdma_cm_id *)event->id;
                ctx = __xsp_rdma_init_ctx(child_cm_id, data);
                if (!ctx) {
			goto err2;
                }

                memset(&conn_param, 0, sizeof conn_param);
                conn_param.responder_resources = 1;
                conn_param.initiator_depth = 1;
		conn_param.private_data = NULL;
		conn_param.private_data_len = 0;

                if (rdma_accept(child_cm_id, &conn_param)) {
                        fprintf(stderr, "%d:%s: rdma_accept failed\n", pid, __func__);
                        goto err1;
                }
                rdma_ack_cm_event(event);
                if (rdma_get_cm_event(data->cm_channel, &event)) {
                        fprintf(stderr, "%d:%s: rdma_get_cm_event error\n", pid, __func__);
                        rdma_destroy_id(child_cm_id);
                        goto err3;
                }
                if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                        fprintf(stderr, "%d:%s: bad event waiting for established %d\n",
                                pid, __func__, event->event);
                        goto err1;
                }
                rdma_ack_cm_event(event);
        } else {
		// use an alternative to CMA here
	}

	freeaddrinfo(res);
        return ctx;

 err1:
        rdma_destroy_id(child_cm_id);
 err2:
        rdma_ack_cm_event(event);
 err3:
        rdma_destroy_id(data->cm_id);
        rdma_destroy_event_channel(data->cm_channel);
 err5:
        return NULL;

}

int xsp_rdma_send_stop(struct xsp_rdma_buf_handle_t *handle)
{
	struct xfer_context *ctx = handle->ctx;

        ctx->send_msg->type = MSG_STOP;
        ctx->send_msg->buffer_id = handle->id;

        __xsp_rdma_send_msg(ctx, 1);
	
	return 0;
}

int xsp_rdma_send_done(struct xsp_rdma_buf_handle_t *handle)
{
	struct xfer_context *ctx = handle->ctx;
	int poll_cq = 1;
	
        if (handle->opcode == IBV_WR_RDMA_WRITE)
		poll_cq = 0;

	ctx->send_msg->type = MSG_DONE;
	ctx->send_msg->buffer_id = handle->id;

	__xsp_rdma_send_msg(ctx, poll_cq);

	return 0;
}

int xsp_rdma_post_buffer(struct xsp_rdma_buf_handle_t *handle)
{
	struct xfer_context *ctx = handle->ctx;

	ctx->send_msg->type = MSG_READY;
	ctx->send_msg->size = handle->size;
	ctx->send_msg->buffer_id = handle->id;

	memcpy(&ctx->send_msg->mr, handle->local_mr, sizeof(struct ibv_mr));
	__xsp_rdma_send_msg(ctx, 1);

	return 0;
}

int xsp_rdma_wait_buffer(struct xsp_rdma_buf_handle_t *handle)
{
        struct xfer_context *ctx = handle->ctx;
        struct ibv_wc wc;

	if (handle->got_done) {
		handle->got_done = 0;
		goto exit;
	}
	
	if (__xsp_rdma_poll_cq(ctx, &wc, 1))
		return -1;

        if (!(wc.opcode & IBV_WC_RECV))
                fprintf(stderr, "%d:%s: bad wc opcode %d\n", pid, __func__,
                        wc.opcode);
        if (wc.wr_id != 0xcafebabe)
                fprintf(stderr, "%d:%s: bad wc wr_id 0x%x\n", pid, __func__,
                        (int)wc.wr_id);
	if (ctx->recv_msg->type != MSG_READY)
                fprintf(stderr, "%d:%s: did not get MSG_READY\n", pid, __func__);
	else {
		if (!handle->remote_mr) {
			handle->remote_mr = malloc(sizeof(struct ibv_mr));
		}
		if (!handle->remote_mr) {
			fprintf(stderr, "%d:%s: could not malloc remote_mr\n", pid, __func__);
			return -1;
		}

		memcpy(handle->remote_mr, &ctx->recv_msg->mr, sizeof(struct ibv_mr));
		if (ctx->recv_msg->size > 0) {
			handle->remote_mr->length = ctx->recv_msg->size;
		}
		handle->remote_size = ctx->recv_msg->size;
	}

 exit:
	// re-arm QP
        __xsp_rdma_post_recv(ctx);
	
	return 0;
}

int xsp_rdma_wait_done(struct xsp_rdma_buf_handle_t *handle)
{
        struct xfer_context *ctx = handle->ctx;
        struct ibv_wc wc;
	
	if (__xsp_rdma_poll_cq(ctx, &wc, 1))
                return -1;

        if (!(wc.opcode & IBV_WC_RECV))
                fprintf(stderr, "%d:%s: bad wc opcode %d\n", pid, __func__,
                        wc.opcode);
        if (wc.wr_id != 0xcafebabe)
                fprintf(stderr, "%d:%s: bad wc wr_id 0x%x\n", pid, __func__,
                        (int)wc.wr_id);

	if (ctx->recv_msg->type != MSG_DONE) {
		fprintf(stderr, "%d:%s: got MSG_STOP\n", pid, __func__);
		return -1;
	}

	// TODO: check id, handle more than one CQE at a time

	// re-arm QP
	__xsp_rdma_post_recv(ctx);

        return 0;	
}

int xsp_rdma_post_os_get(struct xsp_rdma_buf_handle_t *handle)
{
	handle->opcode = IBV_WR_RDMA_READ;
	if (__xsp_rdma_do_rdma(handle) != 0)
                return -1;

	return 0;
}

int xsp_rdma_post_os_put(struct xsp_rdma_buf_handle_t *handle)
{
	handle->opcode = IBV_WR_RDMA_WRITE;
	if (__xsp_rdma_do_rdma(handle) != 0)
		return -1;

	// tell the other side we're done sending
	// will complete after the RDMA_WRITE
	xsp_rdma_send_done(handle);
	
	return 0;
}

int xsp_rdma_wait_os(struct xsp_rdma_buf_handle_t *handle)
{
	struct xfer_context *ctx = handle->ctx;
	struct ibv_wc wc;
	int ccnt;
	int events = 1;

	// if the WR was a WRITE, a close was sent right after
	if (handle->opcode == IBV_WR_RDMA_WRITE)
		events = 2;

	ccnt = 0;
	while (ccnt < events) {
		if (__xsp_rdma_poll_cq(ctx, &wc, 1))
			return -1;
		
		switch (wc.opcode) {
		case IBV_WC_RECV:
			handle->got_done = 1;
			break;
		case IBV_WC_SEND:
		case IBV_WC_RDMA_WRITE:
		case IBV_WC_RDMA_READ:
			ccnt++;
			break;
		default:
			break;
		}
	}

	return 0;
}

int xsp_rdma_register_buffer(struct xfer_context *ctx, struct xsp_rdma_buf_handle_t *handle)
{
	/* We dont really want IBV_ACCESS_LOCAL_WRITE, but IB spec says:
	 * The Consumer is not allowed to assign Remote Write or Remote Atomic to
	 * a Memory Region that has not been assigned Local Write. */
	handle->local_mr = ibv_reg_mr(ctx->pd, handle->buf, handle->size,
				      IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE |
				      IBV_ACCESS_REMOTE_READ);
	if (!handle->local_mr) {
		fprintf(stderr, "%d:%s: Couldn't allocate MR\n", pid, __func__);
		return -1;
	}

	handle->id = (uintptr_t) handle->buf;
	handle->got_done = 0;
	handle->remote_mr = NULL;
	handle->ctx = ctx;

	return 0;
}

int xsp_rdma_unregister_buffer(struct xsp_rdma_buf_handle_t *handle) {
	ibv_dereg_mr(handle->local_mr);
	if (handle->remote_mr)
		free(handle->remote_mr);

	return 0;
}

int xsp_rdma_finalize(struct xfer_data *data)
{
        struct rdma_cm_event *event;
        int rc;

        if (data->servername) {
                rc = rdma_disconnect(data->cm_id);
                if (rc) {
                        perror("rdma_disconnect");
                        fprintf(stderr, "%d:%s: rdma disconnect error\n", pid,
				__func__);
                        return -1;
                }
        }

        rdma_get_cm_event(data->cm_channel, &event);
        if (event->event != RDMA_CM_EVENT_DISCONNECTED)
                fprintf(stderr, "%d:%s: unexpected event during disconnect %d\n",
                        pid, __func__, event->event);

        rdma_ack_cm_event(event);
        rdma_destroy_id(data->cm_id);
        rdma_destroy_event_channel(data->cm_channel);

	return 0;
}

int xsp_rdma_init(struct xfer_data *data)
{
        int                      duplex = 0;
	
	/* Get the PID and prepend it to every output on stdout/stderr
         * This helps to parse output when multiple client/server are
         * run from single host
         */
        pid = getpid();

        printf("%d: | port=%d | ib_port=%d | tx_depth=%d | sl=%d | duplex=%d | cma=%d |\n",
	       pid, data->port, data->ib_port, data->tx_depth, sl, duplex, data->use_cma);

        /* Done with parameter parsing. Perform setup. */

        srand48(pid * time(NULL));

        page_size = sysconf(_SC_PAGESIZE);

        if (data->use_cma) {
                data->cm_channel = rdma_create_event_channel();
                if (!data->cm_channel) {
                        fprintf(stderr, "%d:%s: rdma_create_event_channel failed\n",
				pid, __func__);
                        return 1;
                }
                if (rdma_create_id(data->cm_channel, &data->cm_id, NULL, RDMA_PS_TCP)) {
                        fprintf(stderr, "%d:%s: rdma_create_id failed\n",
				pid, __func__);
                        return 1;
                }
        } else {
		// use an alternative to CMA here
	}
	
	return 0;
}