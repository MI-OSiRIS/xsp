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
	"test res",
	0,
	NULL,
	0,
	NULL,
	10,
	0
};

OSCARS_L2Info l2_info = {
	NULL,
	NULL,
	"vlsr1",
	"vlsr2"
};

OSCARS_pathInfo path_info = {
	"timer-automatic",
	NULL,
	NULL,
	&l2_info,
	NULL,
	NULL
};

OSCARS_createRequest create_request = {
	NULL,
	1301772039,
	1301782039,
	1000,
	"test res",
	&path_info
};

OSCARS_createRequest modify_request = {
	"12345",
	1301772039,
	1301792039,
	2000,
	"modified res",
	&path_info
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
                oscars_pretty_print(GET_TOPO, response);
	}
	else
		printf("error in oscars_getNetworkTopology\n");
	
	sleep(1);

	printf("\nTesting oscars_createReservation\n\n");
	request = (void*) &create_request;
	if (oscars_createReservation(&oscars_soap, request, &response) == 0) {
		oscars_pretty_print(CREATE_RES, response);
        }
        else
                printf("error in oscars_createReservation\n");
	
	sleep(1);

	printf("\nTesting oscars_listReservations\n\n");
	request = (void*) &list_request;
	if (oscars_listReservations(&oscars_soap, request, &response) == 0) {
		oscars_pretty_print(LIST_RES, response);
        }
	else
		printf("error in oscars_listReservations\n");
	
	sleep(1);

	printf("\nTesting oscars_modifyReservation\n\n");
	request = (void*) &modify_request;
        if (oscars_modifyReservation(&oscars_soap, request, &response) == 0) {
                oscars_pretty_print(MODIFY_RES, response);
        }
        else
                printf("error in oscars_modifyReservation\n");

        sleep(1);

	printf("\nTesting oscars_queryReservation\n\n");
        if (oscars_queryReservation(&oscars_soap, "12345", &response) == 0) {
                oscars_pretty_print(QUERY_RES, response);
        }
        else
                printf("error in oscars_queryReservation\n");

        sleep(1);

	printf("\nTesting oscars_cancelReservation\n\n");
	if (oscars_cancelReservation(&oscars_soap, "12345", &response) == 0) {
		oscars_pretty_print(CANCEL_RES, response);
        }
        else
                printf("error in oscars_cancelReservation\n");


	printf("done\n");
	
	xspd_stop_soap_ssl(&oscars_soap);

	return 0;
}

