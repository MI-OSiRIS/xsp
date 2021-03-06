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
/*
 * Example of netlogger calipers usage.
 */
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "netlogger_calipers.h"

static const volatile char rcsid[] = "$Id: netlogger_calipers_example.c 33086 2012-11-12 18:23:45Z dang $";

void usage(const char *s) {
  fprintf(stderr,"%s\n"
          "usage: netlogger_calipers_example [N=num. loops] [M=work/loop]\n", s);
}

#define MAX_WORK 1000
double *do_something(int n) {
  static double a[MAX_WORK];
  int i,j;

  for (i=0; i < n; i++) {
    a[i] = 1.0 * i;
  }
  for (i=0; i < n; i++) {
    for (j=0; j < n; j++) {
      a[j] = a[i] + a[j];
    }
  }
  return a;
}

void run(netlogger_calipers_T c, int numloops, int workperloop) {
  int i;
  double *p;
  for (i=0; i < numloops; i++) {
    netlogger_calipers_begin(c);
    p = do_something(workperloop);
    netlogger_calipers_end(c, 1.234);
  }
}

void report(netlogger_calipers_T c) {
  char *log_event;
  double d;
  int i;
  bson *bdata;

  netlogger_calipers_calc(c);
  printf("Value:\n");
  printf("    sum=%lf mean=%lf\n", c->sum, c->mean);
  log_event = netlogger_calipers_log(c, "example");
  assert(log_event);
  printf("Log event:\n%s\n", log_event);
  /* XXX: why? fwrite(log_event, 1024, 1, stdout); */
  printf("\n");
  free(log_event);
  bdata = netlogger_calipers_psdata(c, "example", "METAID", 1);
  assert(bdata);
  printf("Perfsonar data block (ASCII):\n");
  bson_print(bdata);
  fflush(stdout);
  bson_destroy(bdata);
  free(bdata);
  /* printf("Histogram:\n");
  for (i=0; i < c->h_num; i++) {
      unsigned count = c->h_data[i];
      double p = c->h_min + c->h_width * i;
      printf("%d [%lf - %lf]: %d\n", i, p, p + c->h_width, count);
  }*/
  d = c->dur - c->dur_sum;
  fprintf(stderr, "Overhead:\n"
          "    begin/end pairs per sec: %lf\n"
          "    usec per begin/end pair: %lf\n"
          "    usec overhead per pair: %lf\n"
          "    %%overhead: %lf\n",
          c->count / c->dur,
          c->dur / c->count * 1e6,
          (d / c->count) * 1e6,
          d / c->dur * 100.);
}

int main(int argc, char **argv) {
  int n = 0;
  int m = 0;
  int min_items = 0;
  int i;
  netlogger_calipers_T calipers;

  if (argc > 1) {
    if (sscanf(argv[1], "%d", &n) != 1 || n < 0) {
      usage("first argument (iterations), "
            "if present, must be a positive integer");
      goto ERROR;
    }
  }
  else {
    n = 100;
  }
  if (argc > 2) {
    if (sscanf(argv[2], "%d", &m) != 1 || m < 1 || m >= MAX_WORK) {
      usage("second argument (work per iteration), "
            "if present, must be a positive integer less than 1000");
      goto ERROR;
    }
  }
  else {
    m = 100;
  }
  printf("Run %d iterations\n", n);
  calipers = netlogger_calipers_new(1);

  printf("With manual histogram\n");
  /* note: gap = value/ns, so if value =~ 1 and ~100*work ns per pair
     then range 0.. 100*m is reasonable */
  netlogger_calipers_hist_manual(calipers, 100, 0, 100*m);
  run(calipers, n, m);
  fprintf(stderr,"Results, with manual histogram\n");
  report(calipers);

  printf("With auto histogram (2 runs)\n");
  netlogger_calipers_hist_auto(calipers, 100, 1);
  run(calipers, n, m);
  netlogger_calipers_calc(calipers);
  netlogger_calipers_clear(calipers);
  run(calipers, n, m);
  fprintf(stderr,"Results, with auto histogram\n");
  report(calipers);

  printf("Without histogram\n");
  netlogger_calipers_hist_manual(calipers, 0, 0, 0);
  run(calipers, n, m);
  fprintf(stderr,"Results, without histogram\n");
  report(calipers);

  netlogger_calipers_free(calipers);
  return 0;

ERROR:
  return -1;
}
