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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

#include "xsp_conn.h"
#include "xsp_logger.h"
#include "xsp_settings.h"
#include "xsp_measurement.h"
#include "xsp_session.h"

#include "libxsp.h"
#include "libxsp_proto.h"

xspMsg *__xsp_conn_get_msg_v0(xspConn *conn, unsigned int flags);
xspMsg *__xsp_conn_get_msg_v1(xspConn *conn, unsigned int flags);

xspConn_defStats *xsp_conn_stats_alloc_def() {
  xspConn_defStats *retval;

  retval = malloc(sizeof(xspConn_defStats));
  if (!retval)
    return NULL;

  bzero(retval, sizeof(xspConn_defStats));

  return retval;
}

void xsp_conn_free_stats_def(xspConn *conn) {
  xspConn_defStats *stats = conn->stats_private;

  free(stats);
}

void *xsp_conn_get_priv_data(xspConn *conn) {
  return conn->conn_private;
}

int xsp_conn_default_get_stat(xspConn *conn, uint16_t type, void *optval, size_t *optlen) {
  int retval = -1;

  switch(type) {
  case XSP_STATS_BYTES_READ:
    if (*optlen >= sizeof(uint64_t)) {
      *((uint64_t *) optval) = ((xspConn_defStats *) conn->stats_private)->bytes_read;
      *optlen = sizeof(uint64_t);
      retval = 0;
    }
    break;

  case XSP_STATS_BYTES_WRITTEN:
    if (*optlen >= sizeof(uint64_t)) {
      *((uint64_t *) optval) = ((xspConn_defStats *) conn->stats_private)->bytes_written;
      *optlen = sizeof(uint64_t);
      retval = 0;
    }
    break;

  default:
    break;
  }

  return retval;
}

xspConn *xsp_conn_alloc() {
  xspConn *new_conn;

  new_conn = malloc(sizeof(xspConn));
  if (!new_conn)
    goto error_exit;

  bzero(new_conn, sizeof(xspConn));

  if (pthread_mutex_init(&(new_conn->lock), NULL))
    goto error_exit_conn;

  if (pthread_cond_init(&(new_conn->cond), NULL))
    goto error_exit_mutex;

  return new_conn;

error_exit_mutex:
  pthread_mutex_destroy(&(new_conn->lock));
error_exit_conn:
  free(new_conn);
error_exit:
  return NULL;
}

void xsp_conn_free(xspConn *conn) {
  if (conn->conn_private != NULL)
    conn->free_conn_private2(conn);

  if (conn->stats_private != NULL)
    conn->free_stats2(conn);

  if (conn->settings)
    xsp_settings_free(conn->settings);

  if (conn->description)
    free(conn->description);

  if (conn->id)
    free(conn->id);

  if (conn->hostname)
    free(conn->hostname);

  pthread_mutex_destroy(&(conn->lock));
  pthread_cond_destroy(&(conn->cond));
  free(conn);
}

int xsp_conn_splice(xspConn *src, xspConn *sink, int fd, size_t len, int flags) {
  return src->splice2(src, sink, len, flags);
}

int xsp_conn_src_splice(xspConn *conn, int fd,  size_t len, int flags) {
  return conn->src_splice2(conn, fd, len, flags);
}

int xsp_conn_sink_splice(xspConn *conn, int fd, size_t len, int flags) {
  return conn->sink_splice2(conn, fd, len, flags);
}

int xsp_conn_read(xspConn *conn, void *buf, size_t len, int flags) {
  return conn->read2(conn, buf, len, flags);
}

int xsp_conn_write(xspConn *conn, const void *buf, size_t len, int flags) {
  return conn->write2(conn, buf, len, flags);
}

int xsp_conn_set_session_status(xspConn *conn, int status) {
  return conn->set_session_status2(conn, status);
}

int xsp_conn_setbufsize(xspConn *conn, uint8_t direction, int size) {
  return conn->setbufsize2(conn, direction, size);
}

int xsp_conn_settimeout(xspConn *conn, uint8_t direction, int seconds) {
  return conn->settimeout2(conn, direction, seconds);
}

int xsp_conn_get_stat (xspConn *conn, uint16_t type, void *optval, size_t *optlen) {
  return conn->get_stat2(conn, type, optval, optlen);
}

int xsp_conn_shutdown(xspConn *conn, int side) {
  int n, was_connected;

  was_connected = (conn->status == STATUS_CONNECTED);

  n = conn->shutdown2(conn, side);

  (void)was_connected;
//	if (conn->status == STATUS_UNCONNECTED && was_connected && conn->session) {
//		lsd_session_event(conn->session, XSP_CONN_CLOSED, conn->id);
//	}

  return n;
}

xspMsg *xsp_conn_get_msg(xspConn *conn, unsigned int flags) {
  return conn->get_msg2(conn, flags);
}

uint64_t xsp_conn_send_msg(xspConn *conn, xspMsg *msg, uint16_t opt_type) {
  switch (msg->version) {
  case XSP_v0:
    return conn->send_msg2(conn, msg, NULL);
    break;
  case XSP_v1: {
    xspBlock *block;
    xspBlockList *bl;

    // set block list to NULL if call says no options
    // even if msg_body has junk in it
    if (opt_type == XSP_OPT_NULL) {
      bl = NULL;
      msg->opt_cnt = 0;
      msg->msg_body = NULL;
    }
    // app-defined blocks, add to a new list
    else if ((opt_type == XSP_OPT_APP) && msg->msg_body) {
      bl = xsp_alloc_block_list();
      xsp_block_list_push(bl, (xspBlock*)msg->msg_body);
      msg->opt_cnt = bl->count;
    }
    // app-defined list of blocks
    else if ((opt_type == XSP_OPT_APP_LIST) && msg->msg_body) {
      bl = (xspBlockList*)msg->msg_body;
      msg->opt_cnt = bl->count;
    }
    // let the proto handler try to figure it out based on opt_type
    else if (msg->msg_body) {
      block = xsp_block_new(opt_type, XSP_DEFAULT_SPORT, 0, msg->msg_body);
      bl = xsp_alloc_block_list();
      xsp_block_list_push(bl, block);
      msg->opt_cnt = bl->count;
    }
    // default case, no blocks
    else {
      bl = NULL;
      msg->opt_cnt = 0;
    }

    return conn->send_msg2(conn, msg, bl);
  }
  break;
  default:
    xsp_err(0, "unknown version");
    break;
  }

  return 0;
}

int xsp_conn_default_set_session_status(xspConn *conn, int status) {
  conn->status = status;
  return 0;
}

xspMsg *__xsp_conn_get_msg_v0(xspConn *conn, unsigned int flags) {
  char *buf = NULL;
  char hdr_buf[sizeof(xspMsgHdr)];
  int amt_read, remainder;
  xspMsg *msg;
  xspMsgHdr *hdr;

  // read the header in
  amt_read = xsp_conn_read(conn, hdr_buf, sizeof(xspMsgHdr), MSG_WAITALL);
  if (amt_read < (int)sizeof(xspMsgHdr)) {
    goto error_exit;
  }

  hdr = (xspMsgHdr *) hdr_buf;

  // obtain the length of the message and verify that it fits in bounds
  remainder = ntohs(hdr->length);
  if (remainder < 0 || remainder > XSP_MAX_LENGTH) {
    goto error_exit;
  }

  if (remainder > 0) {
    // allocate space for the remainder
    buf = (char *) malloc(sizeof(char) * remainder);
    if (!buf)
      goto error_exit;

    // grab the remainder
    amt_read = xsp_conn_read(conn, buf, remainder, MSG_WAITALL);
    if (amt_read < remainder) {
      goto error_exit2;
    }
  }

  // allocate a message to return
  msg = (xspMsg *) malloc(sizeof(xspMsg));
  if (!msg) {
    goto error_exit2;
  }

  // fill in the message
  msg->type = hdr->type;
  msg->version = hdr->version;
  bin2hex(hdr->sess_id, msg->sess_id, XSP_SESSIONID_LEN);

  if (xsp_parse_msgbody(msg, buf, amt_read, &(msg->msg_body)) != 0)
    goto error_exit3;

  if (buf)
    free(buf);

  return msg;

error_exit3:
  free(msg);
error_exit2:
  if (buf)
    free(buf);
error_exit:
  return NULL;
}

xspMsg *__xsp_conn_get_msg_v1(xspConn *conn, unsigned int flags) {
  char *buf = NULL;
  char hdr_buf[sizeof(xspv1MsgHdr)];
  char bhdr_buf[sizeof(xspv1BlockHdr)];

  int i;
  int options;
  uint64_t amt_read;
  uint64_t data_size = 0;

  xspMsg *msg;
  xspv1MsgHdr *hdr;
  xspv1BlockHdr *bhdr;
  xspBlock *block;
  xspBlockList *bl;

  // read the header in
  amt_read = xsp_conn_read(conn, hdr_buf, sizeof(xspv1MsgHdr), MSG_WAITALL);

  if (amt_read < (int)sizeof(xspv1MsgHdr)) {
    if (amt_read < 0) {
      //perror("error:");
    }
    goto error_exit;
  }

  hdr = (xspv1MsgHdr *) hdr_buf;

  options = ntohs(hdr->opt_cnt);

  if (options > 0)
    bl = xsp_alloc_block_list();
  else
    bl = NULL;

  for (i = 0; i < options; i++) {
    uint16_t bhdr_len;
    uint16_t bhdr_type;
    uint16_t bhdr_sport;
    uint64_t block_len;

    // get block header
    amt_read = xsp_conn_read(conn, bhdr_buf, sizeof(xspv1BlockHdr), MSG_WAITALL);
    if (amt_read < (int)sizeof(xspv1BlockHdr)) {
      if (amt_read < 0) {
        perror("error:");
      }
      goto error_exit;
    }

    bhdr = (xspv1BlockHdr*) bhdr_buf;

    bhdr_type = ntohs(bhdr->type);
    bhdr_sport = ntohs(bhdr->sport);
    bhdr_len = ntohs(bhdr->length);

    d_printf("block hdr type: %d, len: %d\n", bhdr_type, bhdr_len);

    // figure out the length of the block
    if (bhdr_len == 0xFFFF) {
      uint64_t nbo;
      amt_read = xsp_conn_read(conn, &nbo, sizeof(uint64_t), MSG_WAITALL);
      if (amt_read < (int)sizeof(uint64_t)) {
        if (amt_read < 0) {
          //perror("error:");
        }
        goto error_exit;
      }
      block_len = ntohll(nbo);
    }
    else
      block_len = bhdr_len;

    // we can have empty blocks
    if (block_len > 0) {

      // now allocate space and read the block data
      buf = (char*)malloc(sizeof(char) * block_len);
      if (!buf)
        goto error_exit;

      amt_read = xsp_conn_read(conn, buf, block_len, MSG_WAITALL);
      if (amt_read < block_len) {
        if (amt_read < 0) {
          //perror("error:");
        }
        goto error_exit;
      }

      data_size += amt_read;
    }

    // make a new xspBlock and add it the block list
    block = xsp_block_new(bhdr_type, bhdr_sport, block_len, buf);
    xsp_block_list_push(bl, block);
  }

  // allocate a message to return
  msg = (xspMsg *) malloc(sizeof(xspMsg));
  if (!msg) {
    goto error_exit2;
  }

  // fill in the message
  msg->version = hdr->version;
  msg->flags = hdr->flags;
  msg->type = ntohs(hdr->type);
  msg->opt_cnt = ntohs(hdr->opt_cnt);
  memcpy(&(msg->src_eid), &(hdr->src_eid), sizeof(struct xsp_addr));
  memcpy(&(msg->dst_eid), &(hdr->dst_eid), sizeof(struct xsp_addr));
  bin2hex(hdr->sess_id, msg->sess_id, XSP_SESSIONID_LEN);

  if (xsp_parse_msgbody(msg, bl, data_size, &(msg->msg_body)) != 0)
    goto error_exit3;

  d_printf("returning an xspMsg of type: %d\n", msg->type);

  return msg;

error_exit3:
  free(msg);
error_exit2:
  if (bl)
    xsp_free_block_list(bl, XSP_BLOCK_FREE_DATA);
error_exit:
  return NULL;
}

xspMsg *xsp_conn_default_get_msg(xspConn *conn, unsigned int flags) {
  uint8_t version;
  int amt_read;

  amt_read = xsp_conn_read(conn, &version, sizeof(uint8_t), MSG_WAITALL | MSG_PEEK);
  if (amt_read < (int)sizeof(uint8_t)) {
    if (amt_read < 0) {
      //perror("error:");
    }
    goto error_exit;
  }

  switch (version) {
  case XSP_v0:
    return __xsp_conn_get_msg_v0(conn, flags);
    break;
  case XSP_v1:
    return __xsp_conn_get_msg_v1(conn, flags);
    break;
  default:
    xsp_err(0, "unsupported version");
    goto error_exit;
  }

error_exit:
  return NULL;
}

uint64_t xsp_conn_default_send_msg(xspConn *conn, xspMsg *msg, xspBlockList *bl) {
  char *msg_buf;
  int msg_buf_len;
  int msg_len;
  uint64_t retval;

  msg_buf = (char *) malloc(sizeof(char) * XSP_MAX_LENGTH);
  if (!msg_buf)
    goto error_exit;

  msg_buf_len = XSP_MAX_LENGTH;

  if (msg->src_eid.type == XSP_EID_NULL)
    xsp_set_eid(&(msg->src_eid), conn->description_local, XSP_EID_HOPID);

  if (conn->description && (msg->dst_eid.type == XSP_EID_NULL))
    xsp_set_eid(&(msg->dst_eid), conn->description, XSP_EID_HOPID);

  if (!strlen(msg->sess_id) && conn->session)
    memcpy(msg->sess_id, xsp_session_get_id(conn->session), 2*XSP_SESSIONID_LEN+1);

  msg_len = xsp_writeout_msg(msg_buf, msg_buf_len, msg, bl);
  if (msg_len < 0)
    goto error_exit2;

  retval = xsp_conn_write(conn, msg_buf, msg_len, 0);

  free(msg_buf);

  return retval;

error_exit2:
  free(msg_buf);
error_exit:
  return -1;
}

