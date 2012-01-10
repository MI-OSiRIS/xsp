#ifndef XSP_SOAP_CONTEXT_H
#define XSP_SOAP_CONTEXT_H

#include "stdsoap2.h"

typedef struct xsp_soap_context_t {
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
} xspSoapContext;

int xsp_copy_soap_context(xspSoapContext *src, xspSoapContext *dst);
int xsp_start_soap_ssl(xspSoapContext *sc, int soap_init_flags, int soap_ssl_flags);
int xsp_stop_soap_ssl(xspSoapContext *sc);
int xsp_start_soap(xspSoapContext *sc, int soap_init_flags);
int xsp_stop_soap(xspSoapContext *sc);

#endif
