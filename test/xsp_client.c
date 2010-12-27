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

#include "option_types.h"

#include "libxsp_client.h"

struct sockaddr_in *nameport2sa(const char *name_port);

int main(int argc, char *argv[])
{
	int i;
	libxspSess *sess;

	if (libxsp_init() < 0) {
		perror("libxsp_init(): failed");
		exit(errno);
	}

	sess = xsp_session();
	if (!sess) {
		perror("xsp_session() failed");
		exit(errno);
	}

	xsp_sess_appendchild(sess, argv[argc - 1], XSP_HOP_NATIVE);

	/* argc - 1 is the ultimate dest */
	if (xsp_connect(sess)) {
		perror("xsp_client: connect failed");
		exit(errno);
	}

	char buf[20] = "this is my ledger";

	xsp_send_msg(sess, buf, strlen(buf)+1, PHOTON_DAPL, 0);

	xsp_close(sess);

	return 0;
}
