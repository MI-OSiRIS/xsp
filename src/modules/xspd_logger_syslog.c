#include <stdio.h>
#include <time.h>

#include <unistd.h>
#include <syslog.h>

#include "xspd_modules.h"
#include "xspd_logger.h"
#include "xspd_config.h"

xspdModule *module_info();
static int xspd_logger_syslog_init();
static int xspd_logger_syslog_log_event(xspEvent *event);

static xspdLoggerBackend xspd_logger_syslog_backend = {
	.name = "Syslog",
	.log_event = xspd_logger_syslog_log_event,
};

static xspdModule xspd_logger_syslog_module = {
	.desc = "Syslog Logger Module",
	.dependencies = "",
	.init = xspd_logger_syslog_init,
};


xspdModule *module_info() {
  return &xspd_logger_syslog_module;
}


int xspd_logger_syslog_init() {

	if (xspd_set_logger_backend(&xspd_logger_syslog_backend)) {
		fprintf(stderr, "xspd_logger_syslog_init(): couldn't register logger backend");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

int xspd_logger_syslog_log_event(xspEvent *event) {
	time_t tv;
	struct tm nice_tv;

	time(&tv);
	localtime_r(&tv, &nice_tv);

	syslog(LOG_INFO, "%4d/%02d/%02d %02d:%02d:%02d %s(%u): %s\n",
			nice_tv.tm_year + 1900, nice_tv.tm_mon + 1, nice_tv.tm_mday,
			nice_tv.tm_hour, nice_tv.tm_min, nice_tv.tm_sec,
			xspd_logger_event_type_to_str(event->type), event->level, event->value);

	return 0;
}
