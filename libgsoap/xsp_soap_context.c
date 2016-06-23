// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
#include "xsp_soap_context.h"

int xsp_copy_soap_context(xspSoapContext *src, xspSoapContext *dst) {
	bcopy(src, dst, sizeof(xspSoapContext));
	return 0;
}

int xsp_start_soap_ssl(xspSoapContext *sc, int soap_init_flags, int soap_ssl_flags) {
	struct soap *soap = (struct soap*)malloc(sizeof(struct soap));
	soap_init2(soap, soap_init_flags, soap_init_flags);
	soap_set_namespaces(soap, sc->namespaces);
	soap_ssl_init();

	if (CRYPTO_thread_setup()) {
		fprintf(stderr, "Couldn't setup SSL threads\n");
		return -1;
	} 
	
	if (soap_ssl_client_context(soap,
				    soap_ssl_flags,
				    sc->keyfile,
				    sc->keypass,
				    sc->cacerts,
				    NULL,
				    NULL
				    ))
		{
			soap_print_fault(soap, stderr);
		        //fprintf(stderr, "Could not initialize SOAP SSL context\n");
		        free(soap);
			return -1;
		}

	sc->soap = (void*)(soap);
	return 0;
}

int xsp_stop_soap_ssl(xspSoapContext *sc) {
	if (sc->soap){
	        soap_end(sc->soap);
		soap_done(sc->soap);
		CRYPTO_thread_cleanup(); 
	}
	return 0;
}

int xsp_start_soap(xspSoapContext *sc, int soap_init_flags) {
	struct soap *soap = (struct soap *)malloc(sizeof(struct soap));
        soap_init2(soap, soap_init_flags, soap_init_flags);
        soap_set_namespaces(soap, sc->namespaces);
        sc->soap = (void*)(soap);
        return 0;
}

int xsp_stop_soap(xspSoapContext *sc) {
	if (sc->soap) {
		//soap_end(sc->soap);
		//soap_done(sc->soap);
		free(sc->soap);
	}
        return 0;
}

