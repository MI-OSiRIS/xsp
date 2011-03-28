#include "oscars.h"
#include "oscarsH.h"

int _oscars_wsse_sign(xspdSoapContext *osc) {
	FILE *fd;
	EVP_PKEY *rsa_private_key;
	X509 *cert;
	
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
	
	fd = fopen("/home/ezra/.ssl/oscars-cert.pem", "r");
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

int oscars_listReservations(xspdSoapContext *osc) {
	int ret = 0;
	
	struct ns1__listRequest list_req;
	struct ns1__listReply list_res;
	
	bzero(&list_req, sizeof(struct ns1__listRequest));
	bzero(&list_res, sizeof(struct ns1__listReply));
	
	if (_oscars_wsse_sign(osc) != 0) {
                return -1;
        }

	if (soap_call___ns1__listReservations((struct soap*)osc->soap,
					      osc->soap_endpoint,
					      osc->soap_action,
					      &list_req, &list_res) == SOAP_OK) {
		
		
	}
	
	return ret;
}

int oscars_createReservation(xspdSoapContext *osc) {
	if (_oscars_wsse_sign(osc) != 0) {
                return -1;
        }
	
	return 0;
}

int oscars_cancelReservation(xspdSoapContext *osc, const char *gri, char **res) {
	int ret = 0;
	
	struct ns1__globalReservationId cancel_req;
	char *cancel_res;

	if (_oscars_wsse_sign(osc) != 0) {
		return -1;
	}
	
	if (gri) {
		cancel_req.gri = (char *) gri;
		if (soap_call___ns1__cancelReservation((struct soap*)osc->soap,
						       osc->soap_endpoint,
						       osc->soap_action,
						       &cancel_req, &cancel_res) == SOAP_OK) {
			if (cancel_res)
				*res = strdup(cancel_res);
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
