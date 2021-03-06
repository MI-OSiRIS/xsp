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
#define _GNU_SOURCE

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "xsp_modules.h"
#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_main_settings.h"

#include "compat.h"

#define XSP_MAX_EVENT_ENTRIES   500000
#define XSP_MIN_EVENT_THRESH    0
#define XSP_MAX_EVENT_THRESH    1

#ifdef NETLOGGER
NL_log_T nllog;
NL_summ_T prog_summ, int_summ;

int stream_ids[MAX_ID];
#endif

static int logging_threshold = 0;

static void xsp_logger_read_config();
static void *xsp_logger_thread(void *arg);

static xspLoggerBackend *logger_be;
static pthread_mutex_t logger_be_lock = PTHREAD_MUTEX_INITIALIZER;

static xspEvent ev_list[XSP_MAX_EVENT_ENTRIES];
static int ev_list_num;
static int ev_list_start;
static int ev_list_end;

static pthread_mutex_t ev_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ev_list_cv = PTHREAD_COND_INITIALIZER;

struct xsp_logger_config_t {
  char *backend;
};

static struct xsp_logger_config_t xspLoggerConfig = {
  .backend = "stdout",
};

static void xsp_logger_read_config() {
  char *str_val;

  if (xsp_main_settings_get("logger", "backend", &str_val) == 0) {
    xspLoggerConfig.backend = str_val;
  }
}

int xsp_logger_init(int threshold) {
  char module_name[255];

  xsp_logger_read_config();

  strlcpy(module_name, "logger_", sizeof(module_name));
  strlcat(module_name, xspLoggerConfig.backend, sizeof(module_name));

  if (xsp_load_module(module_name) != 0) {
    fprintf(stderr, "xsp_logger_init(): couldn't load backend: %s", xspLoggerConfig.backend);
    goto error_exit;
  }

  if (logger_be == NULL) {
    fprintf(stderr, "xsp_logger_init(): backend didn't register itself: %s", xspLoggerConfig.backend);
    goto error_exit;
  }

  if (xsp_tpool_exec(xsp_logger_thread, NULL) != 0) {
    fprintf(stderr, "xsp_logger_init(): couldn't startup event logging thread\n");
    goto error_exit;
  }

  logging_threshold = threshold;

  return 0;

error_exit:
  return -1;
}

int xsp_set_logger_backend(xspLoggerBackend *be) {
  pthread_mutex_lock(&logger_be_lock);
  {
    logger_be = be;
  }
  pthread_mutex_unlock(&logger_be_lock);

  return 0;
}

int xsp_log(enum xsp_event_types type, unsigned int level, const char *fmt, ...) {
  int retval;

  if (level > logging_threshold && logging_threshold >= 0)
    return -1;

  pthread_mutex_lock(&ev_list_lock);
  {
    va_list argp;
    int n;

    bzero(&(ev_list[ev_list_end]), sizeof(xspEvent));
    va_start(argp, fmt);
    n = vasprintf(&ev_list[ev_list_end].value, fmt, argp);
    va_end(argp);

    if (n != -1) {
      ev_list[ev_list_end].type = type;
      ev_list[ev_list_end].level = level;
      ev_list[ev_list_end].length = strlen(ev_list[ev_list_end].value);

      ev_list_end = (ev_list_end + 1) % XSP_MAX_EVENT_ENTRIES;
      ev_list_num++;

      pthread_cond_signal(&ev_list_cv);

      retval = 0;
    }
    else {
      retval = -1;
    }

  }
  pthread_mutex_unlock(&ev_list_lock);

  return retval;
}

void *xsp_logger_thread(void *arg) {

  // grab access to the event list
  pthread_mutex_lock(&ev_list_lock);

  while(1) {

    // wait till we hit a threshold
    while (ev_list_num < XSP_MAX_EVENT_THRESH) {
      // the function releases the lock and retakes it before returning
      pthread_cond_wait(&ev_list_cv, &ev_list_lock);
    }

    while (ev_list_num > XSP_MIN_EVENT_THRESH) {

      pthread_mutex_lock(&logger_be_lock);
      {
        logger_be->log_event(&ev_list[ev_list_start]);
      }
      pthread_mutex_unlock(&logger_be_lock);

      free(ev_list[ev_list_start].value);

      // do book keeping
      ev_list_start = (ev_list_start + 1) % XSP_MAX_EVENT_ENTRIES;

      ev_list_num--;
    }
  }

  return NULL;
}

static unsigned int xsp_debug_level;

void xsp_set_debug_level(unsigned int level) {
  xsp_debug_level = level;
}

const char *xsp_logger_event_type_to_str(enum xsp_event_types type) {
  switch(type) {
  case XSP_INFO:
    return "INFO";
    break;
  case XSP_MEAS:
    return "MEAS";
    break;
  case XSP_WARN:
    return "WARN";
    break;
  case XSP_ERR:
    return "ERR";
    break;
  case XSP_DEBUG:
    return "DEBUG";
    break;
  default:
    return "INVALID";
  }
}

void xsp_logger_set_threshold(int threshold) {
  logging_threshold = threshold;
}
