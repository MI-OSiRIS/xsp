#include <stdio.h>
#include <time.h>

#include "xsp_modules.h"
#include "xsp_logger.h"
#include "xsp_config.h"

xspModule *module_info();
static int xsp_logger_file_init();
static int xsp_logger_file_log_event(xspEvent *event);
static void xsp_logger_read_config();

FILE *output_file;

static xspLoggerBackend xsp_logger_file_backend = {
	.name = "File",
	.log_event = xsp_logger_file_log_event,
};

static xspModule xsp_logger_file_module = {
	.desc = "File Logger Module",
	.dependencies = "",
	.init = xsp_logger_file_init,
};

struct xsp_logger_file_config_t {
	char *file;
};

static struct xsp_logger_file_config_t xspLoggerFileConfig = {
	.file = "xsp.out",
};

xspModule *module_info() {
	return &xsp_logger_file_module;
}

static void xsp_logger_read_config() {
	char *str_val;

	if (xsp_main_settings_get("logger", "output_file", &str_val) == 0) {
		xspLoggerFileConfig.file = str_val;
	}
}

int xsp_logger_file_init() {

	xsp_logger_read_config();

	output_file = fopen(xspLoggerFileConfig.file, "a");
	if (!output_file) {
		fprintf(stderr, "xsp_logger_file_init(): couldn't open \"%s\"", xspLoggerFileConfig.file);
		goto error_exit;
	}

	if (xsp_set_logger_backend(&xsp_logger_file_backend)) {
		fprintf(stderr, "xsp_logger_file_init(): couldn't register logger backend");
		goto error_exit2;
	}

	return 0;

error_exit2:
	fclose(output_file);
error_exit:
	return -1;
}

int xsp_logger_file_log_event(xspEvent *event) {
	time_t tv;
	struct tm nice_tv;

	time(&tv);
	localtime_r(&tv, &nice_tv);

	fprintf(output_file, "%4d/%02d/%02d %02d:%02d:%02d %s(%u): %s\n",
		nice_tv.tm_year + 1900, nice_tv.tm_mon + 1, nice_tv.tm_mday,
		nice_tv.tm_hour, nice_tv.tm_min, nice_tv.tm_sec,
		xsp_logger_event_type_to_str(event->type), event->level, event->value);
	fflush(output_file);

	return 0;
}
