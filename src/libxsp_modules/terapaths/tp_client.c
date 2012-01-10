#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "terapaths.h"
#include "tps.nsmap"



typedef struct xspd_terapaths_path_t {
  char *src;
  char *dst;
  
  char *src_ports;
  char *dst_ports;
  
  char *direction;
  char *bw_class;

  uint64_t bw;
  uint64_t start_time;
  uint64_t duration;
} xspdTPSPath;

int main(int argc, char* argv[])
{
  int i, j;
  struct tm tm;

  char *reservation_id;
  char *related_ids;
  char *status;

  xspdTPSPath path;
  xspSoapContext tps_soap;
  struct soap soap;
  
  tpsPath tpsPath;
  tpsBandwidths tpsBW;

  soap_init(&soap);
  soap_set_namespaces(&soap, tps_namespaces); 
  soap_ssl_init();

  if (soap_ssl_client_context(&soap,
			      //SOAP_SSL_REQUIRE_SERVER_AUTHENTICATION
			      SOAP_SSL_SKIP_HOST_CHECK, /* use SOAP_SSL_DEFAULT in production code */
			      "/work/kissel/xspd/etc/doecert-new.pem",       /* keyfile: required only when client must authenticate to 
					     server (see SSL docs on how to obtain this file) */
			      NULL,       /* password to read the keyfile */
			      NULL,      /* optional cacert file to store trusted certificates */
			      NULL,      /* optional capath to directory with trusted certificates */
			      NULL      /* if randfile!=NULL: use a file with random data to seed randomness */ 
			      ))
    { 
      soap_print_fault(&soap, stderr);
      exit(1);
    }
  
  // SOAP context is ready to go
  tps_soap.soap = &soap;
  tps_soap.soap_endpoint = "https://tps.damslab.org:48588/terapathsAPI/tpsAPI";
  tps_soap.soap_action = NULL;

  //configure a terapaths reservation
  path.src = "198.124.220.7";
  path.dst = "198.124.220.135";
  path.src_ports = "22334";
  path.dst_ports = "33445";
  path.bw = 5000000;
  path.bw_class = "AF11";
  path.direction = "bidirectional";

  strptime("2010-5-20 18:30:00", "%Y-%m-%d %H:%M:%S", &tm);
  path.start_time = (uint64_t)mktime(&tm) * (uint64_t)1000;
  path.duration = 600;

  //get paths between src and dst
  printf("\nTesting tpsAPI_getPath\n\n");
  if (terapaths_get_path(&tps_soap, path.src, path.dst, &tpsPath) == 0)
    {
      for (i=0; i < tpsPath.size; i++)
	printf("%d: %s\n", i+1, tpsPath.path[i]);
    }
  
  sleep(1);

  //get bandwidth between src and dst
  printf("\n\nTesting tpsAPI_getBandwidths\n\n");
  if (terapaths_get_bandwidths(&tps_soap, path.src, path.dst, &tpsBW) == 0)
  {
    for (i=0; i < tpsBW.size; i++)
      {
	printf("%d:", i+1);
	if (tpsBW.bws[i]) {
	  for (j=0; j< tpsBW.bws[i]->size; j++)
	    printf(" [%s, %lld]", tpsBW.bws[i]->class[j], tpsBW.bws[i]->bw[j]);
	}
	printf("\n");
      }
  }
  
  sleep(1);

  //make a reservation
  printf("\n\nTesting tpsAPI_reserve\n\n");
  if (terapaths_reserve(&tps_soap, path.src, path.dst, path.src_ports,
			       path.dst_ports, path.direction, path.bw_class, path.bw,
			       path.start_time, path.duration, &reservation_id) == 0)
    {
      printf("Reservation completed with reservation id: %s\n", reservation_id);
    }
  else
    {
      reservation_id = NULL;
      printf("Reservation failed!\n");
    }

  sleep(2);

  //get reservation status
  printf("\n\nTesting tpsAPI_getReservationData (status)\n\n");
  if (terapaths_get_reservation_status(&tps_soap, reservation_id, &status) == 0)
    {
      printf("Reservation status: %s\n", status);
    }
  else
    {
      printf("Could not get reservation status\n");
    }

  sleep(2);
  
  //commit the reservation
  printf("\n\nTesting tpsAPI_commit\n\n");
  if (terapaths_commit(&tps_soap, reservation_id) == 0)
    {
      printf("Commit succeeded.\n");
    }
  else
    {
      printf("Commit failed!\n");
    }

  sleep(2);

  //get related IDs
  printf("\n\nTesting tpsAPI_getRelatedReservationIds\n\n");
  if (terapaths_get_related_ids(&tps_soap, reservation_id, &related_ids) == 0)
    {
      printf("Related reservation IDs string: %s\n", related_ids);
    }
  else
    {
      printf("Could not get related reservation IDs\n");
    }

  sleep(2);

  //cancel the reservation
  printf("\n\nTesting tpsAPI_cancel\n\n");
  if (terapaths_cancel(&tps_soap, reservation_id) == 0)
    {
      printf("Cancel succeeded.\n");
    }
  else
    {
      printf("Cancel failed!\n");
    }

  return 0;
}

