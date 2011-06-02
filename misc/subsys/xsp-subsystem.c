#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <stdarg.h>

#include "libxsp_client.h"

#define SUBSYS_TRACE 1

#define XSP_INSTANCE_ADDR "127.0.0.1"
#define XSP_INSTANCE_PORT 5006

#define XSP_MAX_LENGTH 65536

/* micro second sleep count to get rid of IO timing bug */
#define USLEEP_CNT  5000

enum {
	FALSE = 0,
	TRUE
};

struct sockaddr_in saddr;
int xspsock;

#ifdef SUBSYS_TRACE
static FILE *infile;
static FILE *outfile;
static FILE *errfile;
static int   indirty;
static int   outdirty;
static int   errdirty;
static int   errok;
#endif

static char msgbuff[XSP_MAX_LENGTH];

int send_buff (int fd, const char *buffer, size_t cnt) {
	size_t sent, left;
	ssize_t  retsiz;
	uint32_t   retry_cnt;

	retry_cnt = 5;
	sent = 0;
	left = cnt;

	while (sent < cnt) {
		retsiz = write(fd, buffer, left);
		if (retsiz < 0) {
			switch (errno) {
			case EAGAIN:
			case EBUSY:
				if (--retry_cnt) {
					break;
				} /* else fall through */
			default:
#ifdef SUBSYS_TRACE
				if (errfile) {
					fprintf(errfile, "\nsend_buf error: %d\n", errno);
				}
#endif
				return retsiz;
			}
		} else {
			sent += (size_t)retsiz;
			buffer += retsiz;
			left -= (size_t)retsiz;
		}
	}

	return 0;

} /* send_buff */

static int init_subsys (void) {

	int ret;
	
#ifdef SUBSYS_TRACE
	infile = NULL;
	outfile = NULL;
	errfile = NULL;
	
	indirty = 0;
	outdirty = 0;
	errdirty = 0;
	
	errok = 1;   /* set to 1 to write non-errors to errfile */
	
	/* open the logfiles that should be active */
	
	infile = fopen("/tmp/subsys-in.log", "w"); 
	outfile = fopen("/tmp/subsys-out.log", "w");
	errfile = fopen("/tmp/subsys-err.log", "w");
#endif
		
	/* open a socket to the running XSP instance */
	xspsock = socket(AF_INET, SOCK_STREAM, 0);
	if (xspsock < 0)
		return -1;

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(XSP_INSTANCE_PORT);
	inet_aton(XSP_INSTANCE_ADDR, &(saddr.sin_addr));
	
	ret = connect(xspsock, (struct sockaddr*)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0)
		return -1;

#ifdef SUBSYS_TRACE
	if (infile) {
		fflush(infile);
	}
	if (outfile) {
		fflush(outfile);
	}
	if (errfile) {
		fprintf(errfile, "\ninit_subsys returning");
		fflush(errfile);
	}
#endif

	return 0;
	
} /* init_subsys */


static void cleanup_subsys (void) {
	if (xspsock) {
		close(xspsock);
	}
	
#ifdef SUBSYS_TRACE
	if (infile) {
		fclose(infile);
	}
	if (outfile) {
		fclose(outfile);
	}
	if (errfile) {
		fclose(errfile);
	}
#endif
	
} /* cleanup_subsys */


static int io_loop (void) {
	int  res;
	int  done;
	fd_set    fds;
	int       ret;
	ssize_t   retcnt;
	int cnt;

	res = 0;
	done = FALSE;
	while (!done) {

		FD_ZERO(&fds);
		
		FD_SET(STDIN_FILENO, &fds);
		FD_SET(xspsock, &fds);
		
#ifdef SUBSYS_TRACE
		if (infile && indirty) {
			fflush(infile);
			indirty = 0;
		}
		if (outfile && outdirty) {
			fflush(outfile);
			outdirty = 0;
		}
		if (errfile && errdirty) {
			fflush(errfile);
			errdirty = 0;
		}
#else
		usleep(USLEEP_CNT);
#endif
		
		ret = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
		if (ret < 0) {
#ifdef SUBSYS_TRACE
			if (errfile) {
				fprintf(errfile, "\nxsp select failed (%d)", ret);
				errdirty = 1;
			}
#endif
			res = -1;
			done = TRUE;
			continue;
		} else if (ret == 0) {
#ifdef SUBSYS_TRACE
			if (errfile) {
				fprintf(errfile, "\nxsp select zero exit");
				errdirty = 1;
			}
#endif
			res = 0;
			done = TRUE;
			continue;
		}
		
		/* check any input from client */
		if (FD_ISSET(STDIN_FILENO, &fds)) {
			retcnt = read(STDIN_FILENO, msgbuff, (size_t)XSP_MAX_LENGTH);
			if (retcnt < 0) {
#ifdef SUBSYS_TRACE
				if (errfile) {
					fprintf(errfile, "\nxsp client read failed (%d)",
						retcnt);
					errdirty = 1;
				}
#endif
				res = -1;
				done = TRUE;
				continue;
			} else if (retcnt == 0) {
#ifdef SUBSYS_TRACE
				if (errfile) {
					//fprintf(errfile, "\nxsp client closed connection");
					errdirty = 1;
				}
#endif
				res = 0;
				errok = 0;
				//done = TRUE;
				//continue;
				usleep(100000);
			}
			
#ifdef SUBSYS_TRACE
			if (errfile && errok) {
				/* not an error */
				fprintf(errfile, "\nxsp read client (%d)", retcnt);
				errdirty = 1;
			}
			if (infile) {
				for (cnt = 0; cnt<retcnt; cnt++) {
					fprintf(infile, "%c", msgbuff[cnt]);
				}
				indirty = 1;
			}
#else
			usleep(USLEEP_CNT);
#endif
			
			if (retcnt > 0) {
				/* send this buffer to the xsp instance */
				res = send_buff(xspsock, msgbuff, (size_t)retcnt);
				if (res != 0) {
#ifdef SUBSYS_TRACE
					if (errfile) {
						fprintf(errfile, 
							"\nsend_buff failed (%d)\n", retcnt);
						errdirty = 1;
					}
#endif
					done = TRUE;
					continue;
				}
				
#ifdef SUBSYS_TRACE
				if (errfile && errok) {
					/* not an error */
					fprintf(errfile, "\nsend xsp server (%d)", retcnt);
					errdirty = 1;
				}
#else 
				usleep(USLEEP_CNT);
#endif
			}
		}
		
		/* check any input from the xspserver */
		if (FD_ISSET(xspsock, &fds)) {
			retcnt = recv(xspsock, msgbuff, (size_t)XSP_MAX_LENGTH, 0);
			if (retcnt < 0) {
#ifdef SUBSYS_TRACE
				if (errfile) {
					fprintf(errfile, "\nxsp recv failed (%d)",
						retcnt);
					errdirty = 1;
				}
#endif
				res = -1;
				done = TRUE;
				continue;
			} else if (retcnt == 0) {
#ifdef SUBSYS_TRACE
				if (errfile) {
					fprintf(errfile, "\nxsp recv len 0");
					errdirty = 1;
				}
#endif
				
				res = 0;
				done = TRUE;
				continue;
			}
			
#ifdef SUBSYS_TRACE
			if (errfile && errok) {
				/* not an error */
				fprintf(errfile, "\nxsp read (%d)", retcnt);
				errdirty = 1;
			}
#endif
			/* send this buffer to STDOUT */
			res = send_buff(STDOUT_FILENO, msgbuff, (size_t)retcnt);
			if (res != 0) {
#ifdef SUBSYS_TRACE
				if (errfile) {
					fprintf(errfile, "\nxsp send buff to client failed");
					errdirty = 1;
				}
#endif
				done = TRUE;
				continue;
			}
#ifdef SUBSYS_TRACE
			if (errfile && errok) {
				/* not an error */
				fprintf(errfile, "\nxsp write client (%d)", retcnt);
				errdirty = 1;
			}
#endif
		}
	}
	
	return res;
	
} /* io_loop */



/********************************************************************
* FUNCTION main
*
* STDIN is input from the SSH client (sent to xspserver)
* STDOUT is output to the SSH client (rcvd from xspserver)
* 
* RETURNS:
*   0 if 0
*   1 if error connecting or logging into xspserver
*********************************************************************/
int main (void) {
	int res;
	const char *msg;
	
	res = init_subsys();
	if (res != 0) {
		msg = "init failed";
	}
	
	if (res == 0) {
		res = io_loop();
		if (res != 0) {
			msg = "IO error";
		}
	}
	
	if (res != 0) {
#ifdef SUBSYS_TRACE
		if (errfile) {
			fprintf(errfile, 
				"\nxsp-subsys: %s", msg);
		}
#endif
	}
	
	cleanup_subsys();
	
	if (res != 0) {
		return 1;
	} else {
		return 0;
	}
	
} /* main */

