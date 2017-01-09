// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
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
#include <time.h>

#include "option_types.h"

#include "libxsp_client.h"

/* Remember to set CLIENT_PEM and CLIENT_ROOT. */
int main(int argc, char *argv[]) {
  libxspSess *sess;
  struct timeval t1, t2, t;

  gettimeofday(&t1, NULL);
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

  if (xsp_sess_set_security(sess, NULL, XSP_SEC_SSL)) {
    fprintf(stderr, "could not set requested xsp security method\n");
    exit(-1);
  }

  /* argc - 1 is the ultimate dest */
  if (xsp_connect(sess)) {
    perror("xsp_client: connect failed");
    exit(errno);
  }

  gettimeofday(&t2, NULL);
  timersub(&t2, &t1, &t);

  printf("%f,", t.tv_sec + t.tv_usec / 1000000.0);
  fflush(stdout);

  xsp_close2(sess);

  return 0;
}
