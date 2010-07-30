#include <stdio.h>
#include <time.h>

#include "xspd_modules.h"
#include "xspd_logger.h"

xspdModule *module_info();
int xspd_logger_stdout_init();
int xspd_logger_stdout_log_event(xspEvent *event);

static xspdLoggerBackend xspd_logger_stdout_backend = {
	.name = "Stdout",
	.log_event = xspd_logger_stdout_log_event,
};

static xspdModule xspd_logger_stdout_module = {
	.desc = "Standard Output Logger Module",
	.dependencies = "",
	.init = xspd_logger_stdout_init,
};

xspdModule *module_info() {
	return &xspd_logger_stdout_module;
}

int xspd_logger_stdout_init() {

	if (xspd_set_logger_backend(&xspd_logger_stdout_backend)) {
		fprintf(stderr, "xspd_logger_stdout_init(): couldn't register logger backend");
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}

int xspd_logger_stdout_log_event(xspEvent *event) {
	time_t tv;
	struct tm nice_tv;

	time(&tv);
	localtime_r(&tv, &nice_tv);

	fprintf(stdout, "%4d/%02d/%02d %02d:%02d:%02d %s(%u): %s\n",
			nice_tv.tm_year + 1900, nice_tv.tm_mon + 1, nice_tv.tm_mday,
			nice_tv.tm_hour, nice_tv.tm_min, nice_tv.tm_sec,
			xspd_logger_event_type_to_str(event->type), event->level, event->value);
	return 0;
}
