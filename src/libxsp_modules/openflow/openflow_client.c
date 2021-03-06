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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "controller.h"

int main() {
  char str[64];
  char *argv[2] = {"controller", "ptcp:1716"}; /* openflow offical controller has
                                                details about the input arguments */

  /* first, initialize the controller */
  controller_init(2, argv);

  /* start the controller */
  controller_start();

  wait_for_switch();

  /* add a flow from the console */
  printf("IP address to add: ");
  fgets(str, 64, stdin);
  if(str[strlen(str) - 1] == '\n')
    str[strlen(str) - 1] = '\0';

  printf("adding %s to the switch\n", str);
  of_add_l3_rule(0, str, "10.10.5.1", 0, 0, 100); // hard code the dst to .3

  /* remove a flow */
  printf("IP address to remove: ");
  fgets(str, 64, stdin);
  if(str[strlen(str) - 1] == '\n')
    str[strlen(str) - 1] = '\0';

  printf("removing %s from the switch\n", str);
  of_remove_l3_rule(0, str, "10.10.5.1", 0, 0); // hard code the dst to .3

  /* quit and stop the controller */
  printf("Press Enter to stop the controller and exit\n");
  fgets(str, 64, stdin);
  controller_stop();

  return 0;
}
