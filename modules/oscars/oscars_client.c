#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "oscars.h"
#include "oscars.nsmap"

int main(int argc, char* argv[])
{
	int i, j;	
	char *response = "default";
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
	
	printf("\nTesting oscars_listReservations\n\n");
	if (oscars_listReservations(&oscars_soap) == 0) {
                printf("Response: %s\n", response);
        }

	sleep(1);

	printf("\nTesting oscars_createReservation\n\n");
	if (oscars_createReservation(&oscars_soap) == 0) {
		printf("Response: %s\n", response);
	}
	
	sleep(1);

	printf("\nTesting oscars_cancelReservation\n\n");
	if (oscars_cancelReservation(&oscars_soap, "blah", &response) == 0) {
		printf("Response: %s\n", response);
	}
	
	

	printf("done\n");
	
	xspd_stop_soap_ssl(&oscars_soap);

	return 0;
}

