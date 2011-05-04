#ifndef XSPD_LOGGER_H
#define XSPD_LOGGER_H

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

enum xsp_event_types { XSPD_INVALID = 0, XSPD_INFO, XSPD_MEAS, XSPD_ERR, XSPD_WARN, XSPD_DEBUG };

typedef struct xsp_event {
	enum xsp_event_types type;
	unsigned int level;
	char *value;
	int length;
} xspEvent;

typedef struct xspd_logger_backend_t {
	char *name;
	int (*log_event) (xspEvent *event);
} xspdLoggerBackend;

int xspd_logger_init(int threshold);
int xspd_set_logger_backend(xspdLoggerBackend *logger_be);
int xspd_log(enum xsp_event_types type, unsigned int level, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));
const char *xspd_logger_event_type_to_str(enum xsp_event_types type);
void xspd_logger_set_threshold(int threshold);

#define xspd_debug(lvl, fmt, args...) xspd_log(XSPD_DEBUG, lvl, "%s(): "fmt, __FUNCTION__, ##args)
#define xspd_warn(lvl, fmt, args...) xspd_log(XSPD_WARN, lvl, "%s(): "fmt, __FUNCTION__, ##args)
#define xspd_err(lvl, fmt, args...) xspd_log(XSPD_ERR, lvl, "%s(): "fmt, __FUNCTION__, ##args)
#define xspd_info(lvl, fmt, args...) xspd_log(XSPD_INFO, lvl, "%s(): "fmt, __FUNCTION__, ##args)


#endif
