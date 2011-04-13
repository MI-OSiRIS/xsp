#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "oscars.h"

#ifdef OSCARS5
#include "oscars.nsmap"
#endif

#ifdef OSCARS6
#include "oscars6.nsmap"
#endif


OSCARS_listRequest list_request = {
	0,                                 // num statuses
	NULL,                              // list of statuses
	0,                                 // num times
	NULL,                              // list of start/end times
	NULL,                              // description
	0,                                 // num linkIDs
	NULL,                              // list of linkIDs
	0,                                 // num vlan tags
	NULL,                              // list of vlan tags
	10,                                // max responses
	0                                  // response offset
};

OSCARS_L2Info l2_info = {
	NULL,
	NULL,
	"urn:ogf:network:domain=ion.internet2.edu:node=rtr.hous:port=xe-0/0/0:link=xe-0/0/0.0",
	"urn:ogf:network:domain=ion.internet2.edu:node=rtr.hous:port=xe-1/0/0:link=xe-1/0/0.0"
};

OSCARS_pathInfo path_info = {
	"timer-automatic",
	NULL,
	NULL,
	&l2_info,
	NULL,
	NULL
};

OSCARS_resRequest create_request = {
	NULL,
	1401772039,
	1401782039,
	1000,
	"test res",
	&path_info
};

OSCARS_resRequest modify_request = {
	"ion.internet2.edu-235",
	1371772039,
	1371792039,
	2000,
	"modified res",
	&path_info
};

void usage(char *exec) {
	printf("usage: %s [create | modify | list | query | cancel | topo ] URL\n", exec);
}

int main(int argc, char* argv[])
{
	int i, j;	
	void *response;
	xspdSoapContext oscars_soap;

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	oscars_soap.soap_endpoint = strdup(argv[2]);
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

	if (!strcmp(argv[1], "topo")) {
		printf("\nTesting oscars_getNetworkTopology\n\n");
		if (oscars_getNetworkTopology(&oscars_soap, "all", &response) == 0) {
			oscars_pretty_print(GET_TOPO, response);
		}
		else
			printf("error in oscars_getNetworkTopology\n");
	}
	else if (!strcmp(argv[1], "create")) {
		printf("\nTesting oscars_createReservation\n\n");
		if (oscars_createReservation(&oscars_soap, &create_request, &response) == 0) {
			oscars_pretty_print(CREATE_RES, response);
		}
		else
			printf("error in oscars_createReservation\n");
		
	}
	else if (!strcmp(argv[1], "list")) {
		printf("\nTesting oscars_listReservations\n\n");
		if (oscars_listReservations(&oscars_soap, &list_request, &response) == 0) {
			oscars_pretty_print(LIST_RES, response);
		}
		else
			printf("error in oscars_listReservations\n");
		
	}
	else if (!strcmp(argv[1], "modify")) {
		printf("\nTesting oscars_modifyReservation\n\n");
		if (oscars_modifyReservation(&oscars_soap, &modify_request, &response) == 0) {
			oscars_pretty_print(MODIFY_RES, response);
		}
		else
			printf("error in oscars_modifyReservation\n");
	}
	else if (!strcmp(argv[1], "query")) {
		printf("\nTesting oscars_queryReservation\n\n");
		if (oscars_queryReservation(&oscars_soap, "ion.internet2.edu-228", &response) == 0) {
			oscars_pretty_print(QUERY_RES, response);
		}
		else
			printf("error in oscars_queryReservation\n");
	}
	else if (!strcmp(argv[1], "cancel")) {
		printf("\nTesting oscars_cancelReservation\n\n");
		if (oscars_cancelReservation(&oscars_soap, "ion.internet2.edu-228", &response) == 0) {
			oscars_pretty_print(CANCEL_RES, response);
		}
		else
			printf("error in oscars_cancelReservation\n");
	}
	else
		usage(argv[0]);
	
	xspd_stop_soap_ssl(&oscars_soap);

	return 0;
}

