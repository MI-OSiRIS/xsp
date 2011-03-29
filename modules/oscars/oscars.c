#include "oscars.h"
#include "oscarsH.h"

void *pretty_print(int type, void *res) {
	switch (type) {
		
	  case GET_TOPO:
	  {
		  int i, j, k, l;
		  struct ns3__CtrlPlaneTopologyContent *tmp = 
			  (struct ns3__CtrlPlaneTopologyContent*)res;

		  printf("IDC_ID: %s\n", tmp->idcId);
		  printf("Topology %s\n", tmp->id);
		  for (i=0; i<tmp->__sizedomain; i++) {
			  printf("Domain %s\n", tmp->domain[i]->id);
			  for (j=0; j<tmp->domain[i]->__sizenode; j++) {
				  printf("\tNode %s\n", tmp->domain[i]->node[j]->id);
				  for (k=0; k<tmp->domain[i]->node[j]->__sizeport; k++) {
					  printf("\t\tPort %s\n", tmp->domain[i]->node[j]->port[k]->id);
					  for (l=0; l<tmp->domain[i]->node[j]->port[k]->__sizelink; l++) {
						  printf("\t\t\tLink %s\n", tmp->domain[i]->node[j]->port[k]->link[l]->id);
					  }
				  }
			  }
		  }
	  }
	  break;
	default:
		  break;
	}
}

int _oscars_wsse_sign(xspdSoapContext *osc) {
	FILE *fd;
	EVP_PKEY *rsa_private_key;
	X509 *cert;
	
	soap_wsse_delete_Security((struct soap*)osc->soap);
	soap_wsse_delete_Signature((struct soap*)osc->soap);

	soap_set_omode((struct soap*)osc->soap, SOAP_XML_CANONICAL | SOAP_XML_INDENT | SOAP_IO_CHUNK);
	soap_register_plugin((struct soap*)osc->soap, soap_wsse);
	
	soap_wsse_add_Security((struct soap*)osc->soap);
	
	fd = fopen(osc->wsse_key, "r");
	if (!fd) {
		fprintf(stderr, "Could not open key file!\n");
		return -1;
	}
	rsa_private_key = PEM_read_PrivateKey(fd, NULL, NULL, osc->wsse_pass);
	fclose(fd);
	
	fd = fopen(osc->wsse_cert, "r");
	if (!fd) {
                fprintf(stderr, "Could not open cert file!\n");
                return -1;
        }
	cert = PEM_read_X509(fd, NULL, NULL, NULL);
	fclose(fd);

	soap_wsse_add_Timestamp((struct soap*)osc->soap, "Time", 600);
	
	if (soap_wsse_add_BinarySecurityTokenX509((struct soap*)osc->soap, "binaryToken", cert)
	    || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509((struct soap*)osc->soap, "#binaryToken")
	    || soap_wsse_sign_body((struct soap*)osc->soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_private_key, 0)
	    || soap_wsse_sign_only((struct soap*)osc->soap, "Body")) {
		soap_print_fault((struct soap*)osc->soap, stderr);
		return -1;
	}

	return 0;
}

int oscars_getNetworkTopology(xspdSoapContext *osc, const void *request, void **response) {
	int ret = 0;
	
	struct ns1__getTopologyContent nt_req;
	struct ns1__getTopologyResponseContent nt_res;

	bzero(&nt_res, sizeof(struct ns1__getTopologyResponseContent));
	
	if (_oscars_wsse_sign(osc) != 0) {
                return -1;
        }

	if (request) {
		nt_req.topologyType = (char *)request;

		if (soap_call___ns1__getNetworkTopology((struct soap*)osc->soap,
						      osc->soap_endpoint,
						      osc->soap_action,
						      &nt_req, &nt_res) == SOAP_OK) {
			
			*response = nt_res.ns3__topology;
			
		}
		else {
			soap_print_fault((struct soap *)osc->soap, stderr);
			ret = -1;
		}
        }

	return ret;
}
	

int oscars_listReservations(xspdSoapContext *osc, const void *request, void **response) {
	int ret = 0;
	
	struct ns1__listRequest list_req;
	struct ns1__listReply *list_res = calloc(1, sizeof(struct ns1__listReply));
	
	bzero(&list_req, sizeof(struct ns1__listRequest));

	OSCARS_listRequest *lr = (OSCARS_listRequest *)request;

	// XXX: finish this
	if (lr->description) {
		list_req.description = lr->description;
	}
	
	if (_oscars_wsse_sign(osc) != 0) {
                return -1;
	}
	
	if (soap_call___ns1__listReservations((struct soap*)osc->soap,
					      osc->soap_endpoint,
					      osc->soap_action,
					      &list_req, list_res) == SOAP_OK) {
		*response = list_res;
	}
	else {
		soap_print_fault((struct soap *)osc->soap, stderr);
		ret = -1;
	}
	
	return ret;
}

int oscars_createReservation(xspdSoapContext *osc, const void *request, void **response) {
	if (_oscars_wsse_sign(osc) != 0) {
                return -1;
        }
	
	
	return 0;
}

int oscars_cancelReservation(xspdSoapContext *osc, const void *request, void **response) {
	int ret = 0;
	
	struct ns1__globalReservationId cancel_req;
	char *cancel_res;

	if (_oscars_wsse_sign(osc) != 0) {
		return -1;
	}
	
	if (request) {
		cancel_req.gri = (char *) request;
		if (soap_call___ns1__cancelReservation((struct soap*)osc->soap,
						       osc->soap_endpoint,
						       osc->soap_action,
						       &cancel_req, &cancel_res) == SOAP_OK) {
			if (cancel_res)
				*response = strdup(cancel_res);
			else
				ret = -1;
		}
		else {
			soap_print_fault((struct soap *)osc->soap, stderr);
			ret = -1;
		}
	}
	else {
		ret = -1;
	}
	
	return ret;
}
