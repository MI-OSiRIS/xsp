#include <stdio.h>
#include <time.h>

#include "xspd_modules.h"
#include "xspd_logger.h"
#include "xspd_config.h"

xspdModule *module_info();
static int xspd_logger_file_init();
static int xspd_logger_file_log_event(xspEvent *event);
static void xspd_logger_read_config();

FILE *output_file;

static xspdLoggerBackend xspd_logger_file_backend = {
	.name = "File",
	.log_event = xspd_logger_file_log_event,
};

static xspdModule xspd_logger_file_module = {
	.desc = "File Logger Module",
	.dependencies = "",
	.init = xspd_logger_file_init,
};

struct xspd_logger_file_config_t {
	char *file;
};

static struct xspd_logger_file_config_t xspdLoggerFileConfig = {
	.file = "xspd.out",
};

xspdModule *module_info() {
	return &xspd_logger_file_module;
}

static void xspd_logger_read_config() {
	char *str_val;

	if (xspd_main_settings_get("logger", "output_file", &str_val) == 0) {
		xspdLoggerFileConfig.file = str_val;
	}
}

int xspd_logger_file_init() {

	xspd_logger_read_config();

	output_file = fopen(xspdLoggerFileConfig.file, "a");
	if (!output_file) {
		fprintf(stderr, "xspd_logger_file_init(): couldn't open \"%s\"", xspdLoggerFileConfig.file);
		goto error_exit;
	}

	if (xspd_set_logger_backend(&xspd_logger_file_backend)) {
		fprintf(stderr, "xspd_logger_file_init(): couldn't register logger backend");
		goto error_exit2;
	}

	return 0;

error_exit2:
	fclose(output_file);
error_exit:
	return -1;
}

int xspd_logger_file_log_event(xspEvent *event) {
	time_t tv;
	struct tm nice_tv;

	time(&tv);
	localtime_r(&tv, &nice_tv);

	fprintf(output_file, "%4d/%02d/%02d %02d:%02d:%02d %s(%u): %s\n",
		nice_tv.tm_year + 1900, nice_tv.tm_mon + 1, nice_tv.tm_mday,
		nice_tv.tm_hour, nice_tv.tm_min, nice_tv.tm_sec,
		xspd_logger_event_type_to_str(event->type), event->level, event->value);
	fflush(output_file);

	return 0;
}
