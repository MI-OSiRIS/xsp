// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
#ifndef RDMA_LIB_H
#define RDMA_LIB_H

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

struct message {
  enum {
    MSG_READY,
    MSG_DONE,
    MSG_STOP
  } type;

  struct ibv_mr mr;
  uint64_t size;
  uint64_t buffer_id;
};

struct xfer_context {
  struct ibv_context *context;
  struct ibv_pd      *pd;
  struct ibv_mr      *recv_mr;
  struct ibv_mr      *send_mr;
  struct message     *recv_msg;
  struct message     *send_msg;
  struct ibv_cq      *cq;
  struct ibv_qp      *qp;
  struct rdma_cm_id  *cm_id;
  struct ibv_comp_channel *ch;
  int                 tx_depth;
  struct ibv_sge      list;
  struct ibv_send_wr  wr;
};

// might need this again in the future
// for non CMA
struct xfer_dest {
  int lid;
  int qpn;
  int psn;
  unsigned rkey;
  unsigned long long vaddr;
  unsigned size;
};

struct xfer_data {
  int                             port;
  int                             ib_port;
  int                             tx_depth;
  int                             use_cma;
  int                             sockfd;
  char                            *servername;
  struct ibv_device               *ib_dev;
  struct rdma_event_channel       *cm_channel;
  struct rdma_cm_id               *cm_id;
};

typedef struct xsp_rdma_buf_handle_t {
  int                             opcode;
  int                             got_done;
  void                            *buf;
  uint64_t                        size;
  uint64_t                        remote_size;
  uint64_t                        id;
  struct ibv_mr                   *local_mr;
  struct ibv_mr                   *remote_mr;
  struct xfer_context             *ctx;
} XSP_RDMA_buf_handle;

typedef struct xsp_rdma_poll_info_t {
  int                            opcode;
  int                            status;
  uint64_t                       id;
} XSP_RDMA_poll_info;


int xsp_rdma_init(struct xfer_data *data);
int xsp_rdma_finalize(struct xfer_data *data);
struct xfer_context *xsp_rdma_init_ctx(void *, struct xfer_data *);
void xsp_rdma_destroy_ctx(struct xfer_context *ctx);
struct xsp_rdma_buf_handle_t *xsp_rdma_alloc_handle();

int xsp_rdma_post_os_put(struct xsp_rdma_buf_handle_t **handles, int hcount);
int xsp_rdma_post_os_get(struct xsp_rdma_buf_handle_t **handles, int hcount);
int xsp_rdma_wait_os(struct xsp_rdma_buf_handle_t *handle);
int xsp_rdma_wait_os_event(struct xfer_context *ctx, struct xsp_rdma_poll_info_t *info);

int xsp_rdma_wait_buffer(struct xsp_rdma_buf_handle_t *handle);
int xsp_rdma_post_buffer(struct xsp_rdma_buf_handle_t *handle);

int xsp_rdma_send_stop(struct xsp_rdma_buf_handle_t *handle);
int xsp_rdma_send_done(struct xsp_rdma_buf_handle_t *handle);
int xsp_rdma_wait_done(struct xsp_rdma_buf_handle_t *handle);

struct xfer_context *xsp_rdma_client_connect(struct xfer_data *data);
struct xfer_context *xsp_rdma_server_connect(struct xfer_data *data);

int xsp_rdma_register_buffer(struct xfer_context *ctx, struct xsp_rdma_buf_handle_t *handle);
int xsp_rdma_unregister_buffer(struct xsp_rdma_buf_handle_t *handle);

#endif
