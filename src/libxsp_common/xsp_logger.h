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
#ifndef XSP_LOGGER_H
#define XSP_LOGGER_H

#ifdef NETLOGGER
#include "nl.h"
#include "nltransfer.h"
#include "nlsumm.h"

#define NL_LVL_UDEF NL_LVL_DEBUG
#define MAX_ID 256

extern NL_log_T nllog;
extern NL_summ_T prog_summ, int_summ;

extern int stream_ids[MAX_ID];
#endif

enum xsp_event_types { XSP_INVALID = 0, XSP_INFO, XSP_MEAS, XSP_ERR, XSP_WARN, XSP_DEBUG };

typedef struct xsp_event {
  enum xsp_event_types type;
  unsigned int level;
  char *value;
  int length;
} xspEvent;

typedef struct xsp_logger_backend_t {
  char *name;
  int (*log_event) (xspEvent *event);
} xspLoggerBackend;

int xsp_logger_init(int threshold);
int xsp_set_logger_backend(xspLoggerBackend *logger_be);
int xsp_log(enum xsp_event_types type, unsigned int level, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));
const char *xsp_logger_event_type_to_str(enum xsp_event_types type);
void xsp_logger_set_threshold(int threshold);

#define xsp_debug(lvl, fmt, args...) xsp_log(XSP_DEBUG, lvl, "%s(): "fmt, __FUNCTION__, ##args)
#define xsp_warn(lvl, fmt, args...) xsp_log(XSP_WARN, lvl, "%s(): "fmt, __FUNCTION__, ##args)
#define xsp_err(lvl, fmt, args...) xsp_log(XSP_ERR, lvl, "%s(): "fmt, __FUNCTION__, ##args)
#define xsp_info(lvl, fmt, args...) xsp_log(XSP_INFO, lvl, "%s(): "fmt, __FUNCTION__, ##args)


#endif
