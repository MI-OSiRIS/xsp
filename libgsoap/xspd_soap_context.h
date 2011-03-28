#ifndef XSPDSOAPCONTEXT_H
#define XSPDSOAPCONTEXT_H

#include "stdsoap2.h"

typedef struct xspd_soap_context_t {
	void *soap;
	char *soap_endpoint;
	char *soap_action;
	
	char *keyfile;
	char *keypass;
	char *cacerts;
	
	char *wsse_key;
	char *wsse_pass;
	char *wsse_cert;

	struct Namespace *namespaces;
} xspdSoapContext;

int xspd_copy_soap_context(xspdSoapContext *src, xspdSoapContext *dst);
int xspd_start_soap_ssl(xspdSoapContext *sc, int soap_ssl_flags);
int xspd_stop_soap_ssl(xspdSoapContext *sc);
int xspd_start_soap(xspdSoapContext *sc);
int xspd_stop_soap(xspdSoapContext *sc);

#endif
