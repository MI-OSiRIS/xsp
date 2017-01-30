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

#include "compat.h"
#include "libxsp_client.h"

enum xsp_linuxnet_ops_t {
  XSP_LINUXNET_SET_ROUTE,
  XSP_LINUXNET_SET_IP,
  XSP_LINUXNET_SET_VLAN
};

static char usage[] = "usage: xsp_linuxnet [-V] [-i interface] [-v vlan id]\n"
                      "\t[-a circuit src ip] [-b circuit dst ip]\n"
                      "\t[-s host src ip] [-d host dst ip] [-x src mask] [-y dst mask]\n"
                      "\t[-z] [-r] xsp_hops\n";

int main(int argc, char *argv[]) {
  extern char *optarg;
  extern int errno;
  extern int optind;
  int i, c;
  int do_oscars = 0;
  int remove = 0;

  char *iface = NULL;
  char *vlan = NULL;
  char *csrc = NULL;
  char *cdst = NULL;
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

  while((c = getopt(argc, argv, "i:v:a:b:s:d:x:y:Vzr")) != -1) {
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

    case 'a':
      csrc = strdup(optarg);
      break;

    case 'b':
      cdst = strdup(optarg);
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

  (void)src;
  (void)dmask;
  
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
    rule = xsp_sess_new_net_path_rule(path, "LINUXNET", NULL, 0);
    xsp_sess_set_net_path_rule_op(rule, XSP_LINUXNET_SET_VLAN);

    crit.iface = iface;
    crit.vlan = atoi(vlan);

    if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
      fprintf(stderr, "could not set rule criteria\n");
  }

  if (iface && csrc) {
    rule = xsp_sess_new_net_path_rule(path, "LINUXNET", NULL, 0);
    xsp_sess_set_net_path_rule_op(rule, XSP_LINUXNET_SET_IP);

    crit.iface = iface;
    crit.dst = csrc;
    crit.dst_mask = smask;

    if (vlan)
      crit.vlan = atoi(vlan);

    if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
      fprintf(stderr, "could not set rule criteria\n");
  }

  if (dst && cdst) {
    rule = xsp_sess_new_net_path_rule(path, "LINUXNET", NULL, 0);
    xsp_sess_set_net_path_rule_op(rule, XSP_LINUXNET_SET_ROUTE);

    crit.iface = NULL;
    crit.src = dst;
    crit.dst = cdst;
    crit.src_mask = "255.255.255.255";
    crit.dst_mask = "255.255.255.255";

    if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
      fprintf(stderr, "could not set rule criteria\n");
  }

  if (do_oscars) {
    rule = xsp_sess_new_net_path_rule(path, "OSCARS", NULL, 0);

    crit.vlan = atoi(vlan);
    crit.src = NULL;
    crit.dst = NULL;

    if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
      fprintf(stderr, "could not set rule criteria\n");
  }

  if (xsp_signal_path(sess, path) != 0)
    fprintf(stderr, "signaling path failed\n");

  xsp_close2(sess);

  return 0;
}
