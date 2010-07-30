#include "stdio.h"
#include "mntr.nsmap"
#include "monitoring.h"
#include "string.h"


int main()
{
  struct soap soap;
  xspdSoapContext mntr;

  //char *endpoint = "http://blackseal.damsl.cis.udel.edu:8000/my-soap-service/?service";
  char *endpoint = "http://192.168.1.20:8000/my-soap-service/?service";	

  uint64_t start_time = 1234567890;
  uint64_t duration = 600;
  uint64_t bw = 20000000;
  
  soap_init(&soap);
  soap_set_namespaces(&soap, mntr_namespaces);

  mntr.soap=&soap;
  mntr.soap_endpoint=NULL;
  mntr.soap_action=NULL;
  
  printf("Signaling for new path reservation\n");
  if(monitoring_notify(&mntr,"123123124","udel","bnl","1000-2000","1000-2000",
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

  printf("Signaling for removed path reservation\n");  
  if(monitoring_remove(&mntr,"123123124")==0)
    printf("Signaling is done for removal of path reservation\n");    
  else
    printf("Signaling failed for removal of path reservation\n"); 
  
  sleep(10);

  soap_destroy(&soap); 
  soap_end(&soap); 
  soap_done(&soap); 
  
  return 0;
  
}
