#include "config.h"
#include "compat.h"

#ifdef JUNOS
#include <stdio.h>
#endif

#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "xspd_conn.h"
#include "xspd_logger.h"
#include "xspd_config.h"
#include "xspd_tpool.h"
#include "xspd_session.h"

#include "xspd_protocols.h"
#include "xspd_default_settings.h"
#include "xspd_frontend_default.h"
#include "xspd_modules.h"


void sig_exit(int signal) {
	exit(0);
}

int main(int argc, char *argv[]) {
	int c;
	extern char *optarg;
	static char usage[] = "usage: xspd [-V] [-B] [-c config_file] [-d debug_level]\n";
	int do_background = 0;
	int debug_level = -1;
	int log_syslog = 0;
	char *logger_file = NULL;
	char *pid_file = NULL;
	char *user = NULL;
	char *group = NULL;
	uid_t uid;
	gid_t gid;
	struct group *gr;
	struct passwd *pw;
#ifdef CONFIG_FILE
	char *conf_file = CONFIG_FILE;
#else
	char *conf_file = NULL;
#endif

#ifdef NETLOGGER
	for (c=0; c<MAX_ID; c++)
	  stream_ids[c] = 0;
	
	/* open NetLogger handle, nllog is global */ 
	nllog = NL_open(NULL);
	if (!nllog) {
	  fprintf(stderr, "NETLOGGER: error opening log file\n");
	  exit(-1);
	}
	NL_set_level(nllog, NL_LVL_UDEF);
	
	prog_summ = NL_summ();
	NL_summ_set_shared_output(prog_summ, nllog);
	NL_transfer_init(prog_summ, -1, NL_LVL_UDEF);
	
	if (getenv("NL_LOG_SUMMARY") == NULL)
	  NL_transfer_set_passthrough(prog_summ);
        NL_summ_add_log(prog_summ, nllog);
	
        //int_summ = NL_summ();
        //NL_summ_set_shared_output(int_summ, nllog);
        //NL_transfer_init(int_summ, 1000000, NL_LVL_DEBUG);
        //NL_transfer_set_passthrough(int_summ);
        //NL_summ_add_log(int_summ, nllog);
#endif

	signal(SIGUSR1, sig_exit);
	signal(SIGPIPE, SIG_IGN); 

	while((c = getopt(argc, argv, "Bsd:c:Vo:p:U:G:")) != -1) {
		switch(c) {
			case 'U':
				user = strdup(optarg);
				break;

			case 'G':
				group = strdup(optarg);
				break;

			case 'p':
				pid_file = strdup(optarg);
				break;

			case 'B':
				do_background = 1;
				break;

		        case 's':
			        log_syslog = 1;
			        break;

			case 'd':
				debug_level = atoi(optarg);
				break;

			case 'c':
				conf_file = strdup(optarg);
				break;

			case 'o':
				logger_file = strdup(optarg);
				break;

			case 'V':
				printf("eXtensible Session Protocol Daemon, version 0.5\n");
				exit(1);
				break;

			default:
				fprintf(stderr, usage); 
				exit(1);
		}
	}

	if (xsp_init()) {
		fprintf(stderr, "couldn't initialize xsp protocol handler\n");
		goto error_exit;
	}
	if (xspd_config_read(conf_file)) {
		fprintf(stderr, "reading configuration file failed\n");
		goto error_exit;
	}


	chdir("/tmp");


#if HAVE_SYS_PRCTL_H
	// ensure that we can generate a core dump even if we changed uids
	prctl(PR_SET_DUMPABLE, 1);
#endif

	if (xspd_tpool_init()) {
		xspd_err(0, "couldn't initialize thread pooling system");
		goto error_exit;
	}
	
	if (xspd_modules_init() != 0) {
		xspd_err(0, "couldn't initialize moduler loader");
		goto error_exit;
	}
	if (xspd_logger_init(debug_level)) {
		xspd_err(0, "couldn't initialize the event log");
		goto error_exit;
	}
	if (xspd_sessions_init()) {
		xspd_err(0, "couldn't initialize session system");
		goto error_exit;
	}
	if (xspd_path_handler_init()) {
		xspd_err(0, "couldn't initialize path handler system");
		goto error_exit;
	}
	if (xspd_load_modules() != 0) {
		xspd_err(0, "couldn't load modules");
		goto error_exit;
	}
	if (xspd_frontend_default_start() != 0) {
		xspd_err(0, "couldn't start default frontend");
		goto error_exit;
	}
	pthread_exit(0);

error_exit:
	sleep(1);
	exit(-1);
}
