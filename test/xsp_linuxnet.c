#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "compat.h"
#include "libxsp_client.h"

enum xsp_linuxnet_ops_t {
        XSP_LINUXNET_SET_ROUTE,
        XSP_LINUXNET_SET_IP,
        XSP_LINUXNET_SET_VLAN
};

static char usage[] = "usage: xsp_linuxnet [-V] [-i interface] [-v vlan id]\n"
	"\t[-s src ip address] [-d dst ip address] [-x src mask]\n"
	"\t[-y dst mask] [-z] [-r] xsp_hops\n";

int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int errno;
	extern int optind;
	int i, c;
	int do_oscars = 0;
	int remove = 0;

	char *iface = NULL;
	char *vlan = NULL;
	char *src = NULL;
	char *dst = NULL;
	char *smask = NULL;
	char *dmask = NULL;

	libxspSess *sess;
	libxspSecInfo *sec;
	libxspNetPath *path;
	libxspNetPathRule *rule;
	libxspNetPathRuleCrit crit;

	memset(&crit, 0, sizeof(libxspNetPathRuleCrit));

	while((c = getopt(argc, argv, "i:v:s:d:x:y:Vzr")) != -1) {
		switch(c) {
		case 'V':
			printf("XSP LINUXNET Tester\n");
			printf("%s\n", usage);
			exit(1);
			break;
		
		case 'i':
			iface = strdup(optarg);
			break;
			
		case 'v':
                        vlan = strdup(optarg);
                        break;
			
		case 's':
                        src = strdup(optarg);
                        break;

		case 'd':
                        dst = strdup(optarg);
                        break;

		case 'x':
                        smask = strdup(optarg);
                        break;

		case 'y':
                        dmask = strdup(optarg);
                        break;

		case 'z':
                        do_oscars = 1;
                        break;

		case 'r':
			remove = 1;
			break;

		default:
			fprintf(stderr, usage); 
			exit(1);
		}
	}

	if (optind == argc) {
		printf("Must specify at least one XSP hop\n");
		exit(1);
	}
	
	if (libxsp_init() < 0) {
		perror("libxsp_init(): failed");
		exit(errno);
	}
	
	sess = xsp_session();
	if (!sess) {
		perror("xsp_session() failed");
		exit(errno);
	}

	for(i = optind; i < argc; i++) {
		printf("appending child hop: %s\n", argv[i]);
                xsp_sess_appendchild(sess, argv[i], XSP_HOP_NATIVE);
        }
	
        sec = xsp_sess_new_security("ezra", NULL, "/home/ezra/.ssh/id_rsa_pl.pub",
                                    "/home/ezra/.ssh/id_rsa_pl", NULL);

        if (xsp_sess_set_security(sess, sec, XSP_SEC_NONE)) {
                fprintf(stderr, "could not set requested xsp security method\n");
                exit(-1);
        }

	if (xsp_connect(sess)) {
		perror("xsp_connect() failed");
		exit(errno);
	}
	
	if (remove)
		path = xsp_sess_new_net_path(XSP_NET_PATH_DELETE);
	else
		path = xsp_sess_new_net_path(XSP_NET_PATH_CREATE);
	
	if (iface && vlan) {
		rule = xsp_sess_new_net_path_rule(path, "LINUXNET");
		xsp_sess_set_net_path_rule_op(rule, XSP_LINUXNET_SET_VLAN);

		crit.iface = iface;
		crit.vlan = atoi(vlan);

		if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
			fprintf(stderr, "could not set rule criteria\n");
	}
	
	if (iface && dst && dmask) {
		rule = xsp_sess_new_net_path_rule(path, "LINUXNET");
		xsp_sess_set_net_path_rule_op(rule, XSP_LINUXNET_SET_IP);

		crit.iface = iface;
		crit.dst = dst;
		crit.dst_mask = dmask;

		if (vlan)
			crit.vlan = atoi(vlan);

		if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
                        fprintf(stderr, "could not set rule criteria\n");
	}

	if (src && dst && smask && dmask) {
		rule = xsp_sess_new_net_path_rule(path, "LINUXNET");
                xsp_sess_set_net_path_rule_op(rule, XSP_LINUXNET_SET_ROUTE);

		crit.iface = NULL;
                crit.src = src;
		crit.dst = dst;
		crit.src_mask = smask;
		crit.dst_mask = dmask;

                if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
                        fprintf(stderr, "could not set rule criteria\n");
	}

	if (do_oscars) {
		rule = xsp_sess_new_net_path_rule(path, "OSCARS");

                if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
                        fprintf(stderr, "could not set rule criteria\n");
	}

        if (xsp_signal_path(sess, path) != 0)
		fprintf(stderr, "signaling path failed\n");
	
        xsp_close2(sess);
	
	return 0;
}
