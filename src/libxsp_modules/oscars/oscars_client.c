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

void usage(char *exec) {
	printf("usage: %s IDC_URL [create | modify | list | query | cancel | topo ] PARAMS ...\n", exec);
	printf("\t create PARAMS: l2_src l2_dst src_vlan dst_vlan bandwidth duration start_time end_time\n");
	printf("\t modify PARAMS: gri l2_src l2_dst src_vlan dst_vlan bandwidth duration start_time end_time\n");
	printf("\t   list PARAMS: num_results (default 10)\n");
	printf("\t  query PARAMS: gri\n");
	printf("\t cancel PARAMS: gri\n");
	printf("\t   topo PARAMS: N/A\n");
	printf("\n\n environment variables:\n");
	printf("\t OSCARS_KEY     - Location of keyfile (default ~/.ssl/oscars-key.pem\n");
	printf("\t OSCARS_CERT    - Location of certfile (default ~/.ssl/oscars-cert.pem\n");
	printf("\t OSCARS_KEYPASS - Key password (default NULL)\n");
}

int main(int argc, char* argv[])
{
	int i, j;	
	void *response;
	xspSoapContext oscars_soap;
	char oscars_key[40];
	char oscars_cert[40];
	char *tmp;

	if (argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	oscars_soap.soap_endpoint = strdup(argv[1]);
	oscars_soap.soap_action = NULL;
	
	// setup soap context
	oscars_soap.namespaces = oscars_namespaces;
	oscars_soap.keyfile = NULL;
	oscars_soap.keypass = NULL;
	oscars_soap.cacerts = NULL;

	tmp = getenv("OSCARS_KEY");
	if (tmp)
		oscars_soap.wsse_key = tmp;
	else {
		sprintf(oscars_key, "%s/%s", getenv("HOME"), ".ssl/oscars-key.pem");
		oscars_soap.wsse_key = oscars_key;
	}

	tmp = getenv("OSCARS_CERT");
	if (tmp)
		oscars_soap.wsse_cert = tmp;
	else {
		sprintf(oscars_cert, "%s/%s", getenv("HOME"), ".ssl/oscars-cert.pem");
		oscars_soap.wsse_cert = oscars_cert;
	}

	oscars_soap.wsse_pass = getenv("OSCARS_KEYPASS");

	xsp_start_soap_ssl(&oscars_soap, SOAP_SSL_NO_AUTHENTICATION);

	if (!strcmp(argv[2], "topo")) {
		printf("\noscars_getNetworkTopology\n\n");
		if (oscars_getNetworkTopology(&oscars_soap, "all", &response) == 0) {
			oscars_pretty_print(GET_TOPO, response);
		}
		else
			printf("error in oscars_getNetworkTopology\n");
	}
	else if (!strcmp(argv[2], "create")) {
		time_t stime, etime;
                OSCARS_resRequest create_req = {0};
                OSCARS_pathInfo path_info = {0};
		OSCARS_L2Info l2_info = {0};
                OSCARS_vlanTag l2_stag = {0};
		OSCARS_vlanTag l2_dtag = {0};
		int true = 1;
		
		if (argc < 5) {
			printf("must at least specify src and dst\n");
			exit(1);
		}

		time(&stime);
		stime += 5;
		etime = stime + atoi(argv[8]);

		if ((argc > 8) && argv[9])
			stime = atoi(argv[9]);
		if ((argc > 9) && argv[10])
			etime = atoi(argv[10]);

		l2_info.src_endpoint = argv[3];
		l2_info.dst_endpoint = argv[4];

		if (atoi(argv[5]) > 0) {
			l2_stag.id = argv[5];
			l2_stag.tagged = (enum boolean_*)&true;
		}
		
		if (atoi(argv[6]) > 0) {
			l2_dtag.id = argv[6];
                        l2_dtag.tagged = (enum boolean_*)&true;
                }
		
		l2_info.src_vlan = &l2_stag;
		l2_info.dst_vlan = &l2_dtag;

		path_info.setup_mode = "timer-automatic";
                path_info.type = NULL;
                path_info.ctrl_plane_path_content = NULL;
		path_info.l2_info = &l2_info;
                path_info.l3_info = NULL;
                path_info.mpls_info = NULL;
		
                create_req.res_id = NULL;
                create_req.start_time = (int64_t)stime;
                create_req.end_time = (int64_t)etime;
                create_req.bandwidth = atoi(argv[7]);
                create_req.description = "C client reservation";
                create_req.path_info = &path_info;

		printf("\noscars_createReservation\n\n");
		if (oscars_createReservation(&oscars_soap, &create_req, &response) == 0) {
			oscars_pretty_print(CREATE_RES, response);
		}
		else
			printf("error in oscars_createReservation\n");
		
	}
	else if (!strcmp(argv[2], "list")) {
		OSCARS_listRequest list_request;
		bzero(&list_request, sizeof(OSCARS_listRequest));
		if (argv[3])
			list_request.res_requested = atoi(argv[3]);
		else
			list_request.res_requested = 10;

		printf("\noscars_listReservations\n\n");
		if (oscars_listReservations(&oscars_soap, &list_request, &response) == 0) {
			oscars_pretty_print(LIST_RES, response);
		}
		else
			printf("error in oscars_listReservations\n");
		
	}
	else if (!strcmp(argv[2], "modify")) {
		time_t stime, etime;
		OSCARS_resRequest modify_request;
		OSCARS_pathInfo path_info;
		OSCARS_L2Info l2_info;
		OSCARS_vlanTag l2_stag;
		OSCARS_vlanTag l2_dtag;
		int true = 1;
		
		if (argc < 5) {
			printf("must at least specify src and dst\n");
			exit(1);
		}
		
		time(&stime);
		stime += 5;
		etime = stime + atoi(argv[9]);
		
		if (argv[10])
			stime = atoi(argv[10]);
		if (argv[11])
			etime = atoi(argv[11]);
		
		l2_info.src_endpoint = argv[4];
		l2_info.dst_endpoint = argv[5];
		l2_info.src_vlan = NULL;
		l2_info.dst_vlan = NULL;
	       
		modify_request.res_id = argv[3];
		l2_info.src_endpoint = argv[4];
		l2_info.dst_endpoint = argv[5];
                l2_info.src_vlan = NULL;
                l2_info.dst_vlan = NULL;

		if (argv[6] > 0) {
			l2_stag.id = argv[5];
			l2_stag.tagged = (enum boolean_*)&true;
			l2_info.src_vlan = &l2_stag;
                }

		if (argv[7] > 0) {
                        l2_dtag.id = argv[6];
                        l2_dtag.tagged = (enum boolean_*)&true;
			l2_info.dst_vlan = &l2_dtag;
		}

                path_info.setup_mode = "timer-automatic";
                path_info.type = NULL;
		path_info.ctrl_plane_path_content = NULL;
		path_info.l2_info = &l2_info;
                path_info.l3_info = NULL;
                path_info.mpls_info = NULL;

		modify_request.res_id = NULL;
		modify_request.start_time = (int64_t)stime;
		modify_request.end_time = (int64_t)etime;
		modify_request.bandwidth = atoi(argv[8]);
                modify_request.description = "C client reservation";
		modify_request.path_info = &path_info;

		printf("\noscars_modifyReservation\n\n");
		if (oscars_modifyReservation(&oscars_soap, &modify_request, &response) == 0) {
			oscars_pretty_print(MODIFY_RES, response);
		}
		else
			printf("error in oscars_modifyReservation\n");
	}
	else if (!strcmp(argv[2], "query")) {
		printf("\noscars_queryReservation\n\n");
		if (oscars_queryReservation(&oscars_soap, argv[3], &response) == 0) {
			oscars_pretty_print(QUERY_RES, response);
		}
		else
			printf("error in oscars_queryReservation\n");
	}
	else if (!strcmp(argv[2], "cancel")) {
		printf("\noscars_cancelReservation\n\n");
		if (oscars_cancelReservation(&oscars_soap, argv[3], &response) == 0) {
			oscars_pretty_print(CANCEL_RES, response);
		}
		else
			printf("error in oscars_cancelReservation\n");
	}
	else
		usage(argv[0]);
	
	xsp_stop_soap_ssl(&oscars_soap);

	return 0;
}

