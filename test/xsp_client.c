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
#include <math.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "option_types.h"

#include "compat.h"
#include "libxsp_client.h"

struct sockaddr_in *nameport2sa(const char *name_port);

int main(int argc, char *argv[]) {
  int i;
  int path_count;
  char **xsp_path = NULL;
  libxspSess *sess;
  libxspSecInfo *sec;

  if (libxsp_init() < 0) {
    perror("libxsp_init(): failed");
    exit(errno);
  }

  sess = xsp_session();
  if (!sess) {
    perror("xsp_session() failed");
    exit(errno);
  }

  xsp_path = split(argv[argc - 1], ",", &path_count);

  for (i = 0 ; i < path_count; i++) {
    printf("appending child hop: %s\n", xsp_path[i]);
    xsp_sess_appendchild(sess, xsp_path[i], XSP_HOP_NATIVE);
  }

  sec = xsp_sess_new_security("ezra", NULL, "/home/ezra/.ssh/id_rsa_pl.pub",
                              "/home/ezra/.ssh/id_rsa_pl", NULL);

  if (xsp_sess_set_security(sess, sec, XSP_SEC_NONE)) {
    fprintf(stderr, "could not set requested xsp security method\n");
    exit(-1);
  }

  /* argc - 1 is the ultimate dest */
  if (xsp_connect(sess)) {
    perror("xsp_client: connect failed");
    exit(errno);
  }

  /*
  char buf[20] = "This is a test";
  char *ret_buf = NULL;
  uint64_t ret_len;
  int ret_type;

  xsp_send_msg(sess, buf, strlen(buf)+1, 0x32);
  xsp_recv_msg(sess, (void**)&ret_buf, &ret_len, &ret_type);

  if (ret_buf) {
    ret_buf[ret_len] = '\0';
    printf("got message[%d]: %s\n", ret_type, ret_buf);
    free(ret_buf);
  }
  */

  libxspNetPath *path;
  libxspNetPathRule *rule;
  libxspNetPathRuleCrit crit;

  memset(&crit, 0, sizeof(crit));

  // creates a path with a single rule
  path = xsp_sess_new_net_path(XSP_NET_PATH_CREATE);
  rule = xsp_sess_new_net_path_rule(path, "OSCARS", NULL, 0);

  crit.src="dynes-udel";
  crit.dst="dynes-udel-port-14";
  crit.bandwidth=300000;
  crit.duration=600;
  crit.vlan=605;

  if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
    fprintf(stderr, "could not set rule criteria\n");

  xsp_signal_path(sess, path);

  xsp_close2(sess);

  return 0;
}
