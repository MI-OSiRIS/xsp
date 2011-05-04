#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>

#include "libxsp.h"
#include "libxsp_proto.h"

#include "compat.h"

// XXX: fix this to not allocate an internal structure(probably should swap this
// and xsp_sa2hopid so that xsp_sa2hopid calls this + strdup or something
char *xsp_sa2hopid(const struct sockaddr *sa, SOCKLEN_T sa_len, int resolve) {
	char hop_id[XSP_HOPID_LEN];

	if (!xsp_sa2hopid_r(sa, sa_len, hop_id, sizeof(hop_id), resolve))
		return NULL;

	return strdup(hop_id);
}

char *xsp_sa2hopid_r(const struct sockaddr *sa, SOCKLEN_T sa_len, char *output_buf, size_t buflen, int resolve) {
	char name[INET6_ADDRSTRLEN];
	char port[10];
	int n;
	int flags;

	flags = NI_NUMERICSERV;
	if (resolve) {
		flags |= NI_NAMEREQD;
	} else {
		flags |= NI_NUMERICHOST;
	}

	n = getnameinfo(sa, sa_len, name, sizeof(name), port, sizeof(port), flags);
	if (n < 0) {
		goto error_exit;
	}

	if (snprintf(output_buf, buflen, "%s/%s", name, port) > buflen) {
		goto error_exit;
	}

	return output_buf;

error_exit:
	return NULL;
}

int xsp_parse_hopid(const char *hop_id, char **ret_server, char **ret_port) {
	char *port;
	char *copy = NULL;

	copy = strdup(hop_id);
	if (!copy)
		goto error_exit;

	port = strchr(copy, '/');
	if (!port) {
		d_printf("no / in hop id: %s\n", copy);
		goto error_exit2;
	}

	*port = '\0';
	port++;

	*ret_server = strdup(copy);
	*ret_port = strdup(port);

	free(copy);

	return 0;

error_exit2:
	free(copy);
error_exit:
	return -1;
}

struct addrinfo *xsp_lookuphop(const char *hop_id) {
	char *port;
	char *server;
	struct addrinfo hints;
	struct addrinfo *res;
	int retval;


	if (xsp_parse_hopid(hop_id, &server, &port) < 0) {
		d_printf("hop parsing failed: %s\n", hop_id);
		goto error_exit;
	}

	bzero(&hints, sizeof(struct addrinfo));

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	retval = getaddrinfo(server, port, &hints, &res);
	if (retval != 0) {
		d_printf("gettaddrinfo failed: %s\n", gai_strerror(retval));
		goto error_exit2;
	}

	free(server);
	free(port);

	return res;

error_exit2:
	free(server);
	free(port);
error_exit:
	return NULL;
}

int xsp_make_connection(char *hop_id) {
	struct addrinfo *hop_addrs;
	struct addrinfo *nexthop;
	short connected;
	int s;

	hop_addrs = xsp_lookuphop(hop_id);
	if (!hop_addrs) {
		d_printf("hop lookup failed for: %s\n", hop_id);
		return -1;
	}

	connected = 0;
	for(nexthop = hop_addrs; nexthop != NULL && !connected; nexthop = nexthop->ai_next) {

			if ((s = socket(nexthop->ai_family, nexthop->ai_socktype, nexthop->ai_protocol)) < 0) {
				d_printf("xsp_make_connection(): socket failed: %s\n", strerror(errno));
				continue;
			}

			if(connect(s, nexthop->ai_addr, nexthop->ai_addrlen) < 0) {
				d_printf("xsp_make_connection(): connect failed: %s\n", strerror(errno));
				continue;
			}

			connected = 1;
	}

	freeaddrinfo(hop_addrs);

	if (!connected)
		return -1;

	return s;
}

/* XXX: could sepecify which versions we want to allow */
int xsp_init() {
	return xsp_proto_init();
}

int gen_rand_hex_lrand(char *output_buf, int size) {
    int i;

    if (size % 2 == 0)
        return -1;

    for(i = 0; i+2 <= size - 1; i+=2) {
        uint8_t l = lrand48();

        sprintf(output_buf + i, "%02X", l);
    }

    output_buf[i] = '\0';

    return 0;
}

int gen_rand_hex_file(char *output_buf, int size) {
    int i;
    int fd = -1;
    int n;

    if (size % 2 == 0)
        return -1;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        d_printf("/dev/urandom couldn't be opened. trying /dev/random.\n");
        fd = open("/dev/random", O_RDONLY);
        if (fd == -1) {
            d_printf("/dev/random couldn't be opened.  going to generic time/pid/ppd method.\n");
            goto error_out;
        } else {
            d_printf("using /dev/random\n");
            ;
        }
    } else {
        d_printf("using /dev/urandom\n");
        ;
    }

    for(i = 0; i+2 <= size - 1; i+=2) {
        uint8_t l;

        n = read(fd, &l, sizeof(l));
        if (n != sizeof(l)) {
            d_printf("read less than the requested size, going to generic time/pid/ppd method.");
            goto error_out;
        }

        sprintf(output_buf + i, "%02X", l);
    }

    d_printf("read %d bytes from random source\n", n);

    close(fd);

    output_buf[i] = '\0';

    return 0;

error_out:
    return -1;
}

int gen_rand_hex(char *output_buf, int size) {
    int n = gen_rand_hex_file(output_buf, size);

    if (n != 0) {
        n = gen_rand_hex_lrand(output_buf, size);
    }

    return n;
}

long gen_rand_seed() {
	long int seed;

	FILE* fstr = fopen("/dev/urandom", "r");

	if (!fstr) {
		d_printf("/dev/urandom couldn't be opened. trying /dev/random.\n");
		fstr = fopen("/dev/random", "r");
		if (!fstr) {
			d_printf("/dev/random couldn't be opened.  going to generic time/pid/ppd method.\n");
			goto generic_out;
		} else {
			d_printf("using /dev/random\n");
			;
		}
	} else {
		d_printf("using /dev/urandom\n");
		;
	}

	fscanf(fstr, "%l", &seed);

	// XXX: gross hack, but can't figure out why OSX hangs on this close
#ifndef __APPLE__
	fclose(fstr);
#endif

	return seed;
 generic_out:
	return time(NULL) * (1+getpid()) * (1+getppid());
}
