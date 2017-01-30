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

static char usage[] = "usage: xsp_pathtest [-Vr] [-e eid]\n"
                      "\t[-s src] [-d dst] [-a dl_src] [-b dl_dst]\n"
                      "\t[-i in_port] [-o out_port] [-v vlan id] xsp_hops\n";

int main(int argc, char *argv[]) {
  extern char *optarg;
  extern int errno;
  extern int optind;
  int i, c;
  int remove = 0;

  char *vlan = NULL;
  char *dlsrc = NULL;
  char *dldst = NULL;
  char *src = NULL;
  char *dst = NULL;
  char *inp = NULL;
  char *outp = NULL;
  char *eid = NULL;

  libxspSess *sess;
  libxspSecInfo *sec;
  libxspNetPath *path;
  libxspNetPathRule *rule;
  libxspNetPathRuleCrit crit;

  memset(&crit, 0, sizeof(libxspNetPathRuleCrit));

  while((c = getopt(argc, argv, "v:e:a:b:s:d:i:o:Vr")) != -1) {
    switch(c) {
    case 'V':
      printf("XSP PATH Tester\n");
      printf("%s\n", usage);
      exit(1);
      break;

    case 'v':
      vlan = strdup(optarg);
      break;

    case 'e':
      eid = strdup(optarg);
      break;

    case 'a':
      dlsrc = strdup(optarg);
      break;

    case 'b':
      dldst = strdup(optarg);
      break;

    case 's':
      src = strdup(optarg);
      break;

    case 'd':
      dst = strdup(optarg);
      break;

    case 'i':
      inp = strdup(optarg);
      break;

    case 'o':
      outp = strdup(optarg);
      break;

    case 'r':
      remove = 1;
      break;

    default:
      fprintf(stderr, usage);
      exit(1);
    }
  }

  (void)dldst;
  (void)dlsrc;
  
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


  rule = xsp_sess_new_net_path_rule(path, "FLOODLIGHT");

  crit.src = src;
  crit.dst = dst;

  if (inp)
    crit.src_port = atoi(inp);
  if (outp)
    crit.dst_port = atoi(outp);
  if (vlan) {
    crit.src_vlan = atoi(vlan);
    crit.vlan = atoi(vlan);
  }

  if (eid)
    xsp_sess_set_net_path_rule_eid(rule, eid, XSP_EID_DPIDC);

  if (xsp_sess_set_net_path_rule_crit(rule, &crit) != 0)
    fprintf(stderr, "could not set rule criteria\n");

  if (xsp_signal_path(sess, path) != 0)
    fprintf(stderr, "signaling path failed\n");

  xsp_close2(sess);

  return 0;
}
