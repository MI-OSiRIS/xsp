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
#include "stdio.h"
#include "mntr.nsmap"
#include "monitoring.h"
#include "string.h"


int main() {
  struct soap soap;
  xspSoapContext mntr;

  char *endpoint = "http://blackseal.damsl.cis.udel.edu/escpscope/monitor-service/?service";
  //char *endpoint = "http://192.168.1.20:8000/monitor-service/?service";

  uint64_t start_time = 1234567890;
  uint64_t duration = 600;
  uint64_t bw = 20000000;

  soap_init(&soap);
  soap_set_namespaces(&soap, mntr_namespaces);

  mntr.soap=&soap;
  mntr.soap_endpoint=endpoint;
  mntr.soap_action=NULL;

  printf("Signaling for new path reservation\n");
  if(monitoring_notify(&mntr,"123123124","198.124.220.194","198.124.220.137","1000-2000","1000-3000",
                       "3019","sender", start_time, duration, bw, "EF", "pending") == 0)
    printf("Signaling is done for notification of path reservation\n");
  else
    printf("Signaling failed for notification of path reservation\n");

  printf("\n------------------------------------------------------------------\n");

  sleep(10);

  printf("Signaling for activation of path reservation\n");
  if(monitoring_set_status(&mntr,"123123124","active")==0)
    printf("Signaling is done for activation of path reservation\n");
  else
    printf("Signaling failed for activation of path reservation\n");

  printf("\n------------------------------------------------------------------\n");

  sleep(10);

  printf("Signaling for update of path reservation\n");
  if(monitoring_update_path(&mntr,"123123124", NULL, NULL, "5000", "2000", "4567",
                            "bidirectional", 0, 9000, 34000, "EK", "active")==0)
    printf("Signaling is done for update of path reservation\n");
  else
    printf("Signaling failed for update of path reservation\n");

  printf("\n------------------------------------------------------------------\n");

  sleep(10);

  printf("Signaling for removed path reservation\n");
  if(monitoring_remove(&mntr,"123123124")==0)
    printf("Signaling is done for removal of path reservation\n");
  else
    printf("Signaling failed for removal of path reservation\n");

  soap_destroy(&soap);
  soap_end(&soap);
  soap_done(&soap);

  return 0;

}
