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
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <web100/web100.h>

#include "xsp_web100.h"
#include "xsp_measurement.h"
#include "xsp_logger.h"

static int __xsp_web100_get_var(web100_agent *agent, web100_connection *conn, char *varname, void *opt, int *optlen);
static int __xsp_web100_get_saved_stat(xspConn *xsp_conn, uint16_t type, void *optval, SOCKLEN_T *optlen);
static int __xsp_web100_get_stat(xspConn *xsp_conn, uint16_t type, void *optval, SOCKLEN_T *optlen);

int xsp_web100_init() {
  return 0;
}

xspConn_web100Stats *xsp_alloc_web100_stats(int sd) {
  xspConn_web100Stats *stats;

  stats = malloc(sizeof(xspConn_web100Stats));
  if (!stats) {
    xsp_err(0, "couldn't allocate stats structure");
    goto error_exit;
  }

  bzero(stats, sizeof(xspConn_web100Stats));

  if (pthread_mutex_init(&(stats->lock), NULL) < 0) {
    xsp_err(0, "couldn't initialize mutex");
    goto error_exit2;
  }

  stats->agent = web100_attach(WEB100_AGENT_TYPE_LOCAL, NULL);
  if (!stats->agent) {
    xsp_err(0, "couldn't attach agent");
    goto error_exit3;
  }

  stats->conn = web100_connection_from_socket(stats->agent, sd);
  if (!stats->conn) {
    xsp_err(0, "couldn't make connection from socket");
    goto error_exit4;
  }


  return stats;

error_exit4:
  web100_detach(stats->agent);
error_exit3:
  pthread_mutex_destroy(&(stats->lock));
error_exit2:
  free(stats);
error_exit:
  return NULL;
}

void xsp_web100_free_stats(void *arg) {
  xspConn_web100Stats *stats = arg;

  web100_detach(stats->agent);
  free(stats);
}

int xsp_web100_get_stat(xspConn *xsp_conn, uint16_t type, void *optval, SOCKLEN_T *optlen) {
  xspConn_web100Stats *stats = xsp_conn->stats_private;
  int n;

  pthread_mutex_lock(&(stats->lock));
  {
    if (stats->saved_state)
      n = __xsp_web100_get_saved_stat(xsp_conn, type, optval, optlen);
    else
      n = __xsp_web100_get_stat(xsp_conn, type, optval, optlen);
  }
  pthread_mutex_unlock(&(stats->lock));

  return n;
}

void xsp_web100_save_stats(xspConn *conn, xspConn_web100Stats *stats) {
  float rtt;
  uint64_t val64;
  uint32_t val32;
  SOCKLEN_T size;

  size = sizeof(rtt);
  if (__xsp_web100_get_stat(conn, XSP_STATS_RTT, &rtt, &size) == 0) {
    stats->rtt = rtt;
  }
  else {
    stats->rtt = 0;
  }

  size = sizeof(val64);
  if (__xsp_web100_get_stat(conn, XSP_STATS_BYTES_READ, &val64, &size) == 0) {
    stats->bytes_in = val64;
  }
  else {
    stats->bytes_in = 0;
  }

  size = sizeof(val64);
  if (__xsp_web100_get_stat(conn, XSP_STATS_BYTES_WRITTEN, &val64, &size) == 0) {
    stats->bytes_out = val64;
  }
  else {
    stats->bytes_out = 0;
  }

  size = sizeof(val32);
  if (__xsp_web100_get_stat(conn, XSP_STATS_BYTES_RETRANSMITTED, &val32, &size) == 0) {
    stats->bytes_retr = val32;
  }
  else {
    stats->bytes_retr = 0;
  }
}

int __xsp_web100_get_saved_stat(xspConn *xsp_conn, uint16_t type, void *optval, SOCKLEN_T *optlen) {
  xspConn_web100Stats *stats = xsp_conn->stats_private;
  int retval = -1;

  switch(type) {
  case XSP_STATS_RTT:
    if (*optlen >= sizeof(stats->rtt)) {
      *((float *)optval) = stats->rtt;
      *optlen = sizeof(stats->rtt);
      retval = 0;
    }
    break;

  case XSP_STATS_BYTES_READ:
    if (*optlen >= sizeof(stats->bytes_in)) {
      *((uint64_t *)optval) = stats->bytes_in;
      *optlen = sizeof(stats->bytes_in);
      retval = 0;
    }
    break;

  case XSP_STATS_BYTES_WRITTEN:
    if (*optlen >= sizeof(stats->bytes_out)) {
      *((uint64_t *)optval) = stats->bytes_out;
      *optlen = sizeof(stats->bytes_out);
      retval = 0;
    }
    break;

  case XSP_STATS_BYTES_RETRANSMITTED:
    if (*optlen >= sizeof(stats->bytes_retr)) {
      *((uint32_t *)optval) = stats->bytes_retr;
      *optlen = sizeof(stats->bytes_retr);
      retval = 0;
    }
    break;
  }

  return retval;
}

int __xsp_web100_get_stat(xspConn *xsp_conn, uint16_t type, void *optval, SOCKLEN_T *optlen) {
  int retval = -1;
  web100_agent *agent = ((xspConn_web100Stats *) xsp_conn->stats_private)->agent;
  web100_connection *conn = ((xspConn_web100Stats *) xsp_conn->stats_private)->conn;

  switch(type) {
  case XSP_STATS_RTT: {
    float avg;
    uint64_t sum_rtt;
    int sum_rtt_size = sizeof(sum_rtt);
    uint32_t count_rtt;
    int count_rtt_size = sizeof(count_rtt);

    if (*optlen >= sizeof(avg)) {
      int n1, n2;

      n1 = __xsp_web100_get_var(agent, conn, "SumRTT", &sum_rtt, &sum_rtt_size);
      n2 = __xsp_web100_get_var(agent, conn, "CountRTT", &count_rtt, &count_rtt_size);

      if (n1 == WEB100_TYPE_COUNTER64 && n2 == WEB100_TYPE_COUNTER32) {
        avg = ((float) sum_rtt)/count_rtt;

        *((float *)optval) = avg;
        *optlen = sizeof(avg);
        retval = 0;
      }
    }

  }
  break;

  case XSP_STATS_BYTES_READ: {
    uint64_t bytes_in;
    int bytes_in_size = sizeof(bytes_in);

    if (*optlen >= sizeof(uint64_t)) {
      int n;

      n = __xsp_web100_get_var(agent, conn, "DataBytesIn", &bytes_in, &bytes_in_size);
      if (n == WEB100_TYPE_COUNTER64) {
        *((uint64_t *)optval) = bytes_in;
        *optlen = sizeof(bytes_in);
        retval = 0;
      }
    }

  }
  break;

  case XSP_STATS_BYTES_WRITTEN: {
    uint64_t bytes_out;
    int bytes_out_size = sizeof(bytes_out);

    if (*optlen >= sizeof(uint64_t)) {
      int n;

      n = __xsp_web100_get_var(agent, conn, "DataBytesOut", &bytes_out, &bytes_out_size);
      if (n == WEB100_TYPE_COUNTER64) {
        *((uint64_t *)optval) = bytes_out;
        *optlen = sizeof(bytes_out);
        retval = 0;
      }
    }

  }
  break;

  case XSP_STATS_BYTES_RETRANSMITTED: {
    uint32_t bytes_retr;
    int bytes_retr_size = sizeof(bytes_retr);

    if (*optlen >= sizeof(uint32_t)) {
      int n;

      n = __xsp_web100_get_var(agent, conn, "BytesRetrans", &bytes_retr, &bytes_retr_size);
      if (n == WEB100_TYPE_COUNTER32) {
        *((uint32_t *)optval) = bytes_retr;
        *optlen = sizeof(bytes_retr);
        retval = 0;
      }
    }

  }
  break;

  default:
    retval = -1;
    break;
  }
  return retval;
}

static int __xsp_web100_get_var(web100_agent *agent, web100_connection *conn, char *varname, void *opt, int *optlen) {
  web100_group *group;
  web100_var *var;
  int var_len;
  int retval;
  int n;

  n = web100_agent_find_var_and_group(agent, varname, &group, &var);
  if (n != WEB100_ERR_SUCCESS) {
    goto error_exit;
  }

  var_len = web100_get_var_size(var);

  if (*optlen < var_len) {
    goto error_exit;
  }

  n = web100_raw_read(var, conn, opt);
  if (n  != WEB100_ERR_SUCCESS) {
    goto error_exit;
  }

  *optlen = var_len;

  retval = web100_get_var_type(var);

  return retval;

error_exit:
  return -1;
}

int xsp_web100_get_var(int sockfd, char *varname, void *opt, int *optlen) {
  web100_connection *conn;
  web100_agent *agent;

  agent = web100_attach(WEB100_AGENT_TYPE_LOCAL, NULL);
  if (!agent)
    goto error_exit;

  conn = web100_connection_from_socket(agent, sockfd);
  if (!conn)
    goto error_exit2;

  return __xsp_web100_get_var(agent, conn, varname, opt, optlen);

error_exit2:
  web100_detach(agent);
error_exit:
  return -1;
}
