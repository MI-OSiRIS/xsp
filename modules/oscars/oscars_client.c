#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "oscars.h"
#include "oscars.nsmap"

OSCARS_listRequest list_request = {
	0,
	NULL,
	0,
	NULL,
	"test reservation",
	0,
	NULL,
	0,
	NULL,
	10,
	0
};



int main(int argc, char* argv[])
{
	int i, j;	
	void *response;
	void *request;
	xspdSoapContext oscars_soap;

	oscars_soap.soap_endpoint = "https://192.168.1.103:8443/axis2/services/OSCARS";
	oscars_soap.soap_action = NULL;
	
	// setup soap context
	oscars_soap.namespaces = oscars_namespaces;
	oscars_soap.keyfile = NULL;
	oscars_soap.keypass = NULL;
	oscars_soap.cacerts = NULL;
	oscars_soap.wsse_key = "/home/ezra/.ssl/oscars-key.pem";
	oscars_soap.wsse_pass = NULL;
	oscars_soap.wsse_cert = "/home/ezra/.ssl/oscars-cert.pem";

	xspd_start_soap_ssl(&oscars_soap, SOAP_SSL_NO_AUTHENTICATION);
	
	printf("\nTesting oscars_getNetworkTopology\n\n");
	request = (void*) "all";
        if (oscars_getNetworkTopology(&oscars_soap, request, &response) == 0) {
                pretty_print(GET_TOPO, response);
	}
	
	sleep(1);

	printf("\nTesting oscars_listReservations\n\n");
	request = (void*) &list_request;
	if (oscars_listReservations(&oscars_soap, request, &response) == 0) {
		pretty_print(LIST_RES, response);
        }

	exit(1);

	sleep(1);

	printf("\nTesting oscars_createReservation\n\n");
	if (oscars_createReservation(&oscars_soap) == 0) {
		printf("Response: %s\n", response);
	}
	
	sleep(1);

	printf("\nTesting oscars_cancelReservation\n\n");
	if (oscars_cancelReservation(&oscars_soap, "blah", &response) == 0) {
		printf("Response: %s\n", (char*)response);
	}
	
	

	printf("done\n");
	
	xspd_stop_soap_ssl(&oscars_soap);

	return 0;
}

