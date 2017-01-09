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
#include <time.h>

#include "xsp_modules.h"
#include "xsp_logger.h"

xspModule *module_info();
int xsp_logger_stdout_init();
int xsp_logger_stdout_log_event(xspEvent *event);

static xspLoggerBackend xsp_logger_stdout_backend = {
  .name = "Stdout",
  .log_event = xsp_logger_stdout_log_event,
};

static xspModule xsp_logger_stdout_module = {
  .desc = "Standard Output Logger Module",
  .dependencies = "",
  .init = xsp_logger_stdout_init,
};

xspModule *module_info() {
  return &xsp_logger_stdout_module;
}

int xsp_logger_stdout_init() {

  if (xsp_set_logger_backend(&xsp_logger_stdout_backend)) {
    fprintf(stderr, "xsp_logger_stdout_init(): couldn't register logger backend");
    goto error_exit;
  }

  return 0;

error_exit:
  return -1;
}

int xsp_logger_stdout_log_event(xspEvent *event) {
  time_t tv;
  struct tm nice_tv;

  time(&tv);
  localtime_r(&tv, &nice_tv);

  fprintf(stdout, "%4d/%02d/%02d %02d:%02d:%02d %s(%u): %s\n",
          nice_tv.tm_year + 1900, nice_tv.tm_mon + 1, nice_tv.tm_mday,
          nice_tv.tm_hour, nice_tv.tm_min, nice_tv.tm_sec,
          xsp_logger_event_type_to_str(event->type), event->level, event->value);
  return 0;
}
