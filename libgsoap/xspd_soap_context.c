#include "xspd_soap_context.h"

int xspd_copy_soap_context(xspdSoapContext *src, xspdSoapContext *dst) {
	bcopy(src, dst, sizeof(xspdSoapContext));
	return 0;
}

int xspd_start_soap_ssl(xspdSoapContext *sc) {
	struct soap *soap = (struct soap *)malloc(sizeof(struct soap));
	soap_init(soap);
	soap_set_namespaces(soap, sc->namespaces);
	soap_ssl_init();

	if (CRYPTO_thread_setup()) {
		xspd_err(0, "Couldn't setup SSL threads");
		return -1;
	} 
	
	if (soap_ssl_client_context(soap,
				    SOAP_SSL_REQUIRE_SERVER_AUTHENTICATION
				    | SOAP_SSL_SKIP_HOST_CHECK,
				    sc->keyfile,
				    sc->keypass,
				    sc->cacerts,
				    NULL,
				    NULL
				    ))
		{
			//soap_print_fault(soap, stderr);
			xspd_err(0, "Could not initialize SOAP SSL context");
			return -1;
		}

	sc->soap = (void*)(soap);
	return 0;
}

int xspd_stop_soap_ssl(xspdSoapContext *sc) {
	if (sc->soap){
		soap_done(sc->soap);
		CRYPTO_thread_cleanup(); 
		free(sc->soap);
	}
	return 0;
}

int xspd_start_soap(xspdSoapContext *sc) {
	struct soap *soap = (struct soap *)malloc(sizeof(struct soap));
        soap_init(soap);
        soap_set_namespaces(soap, sc->namespaces);
        sc->soap = (void*)(soap);
        return 0;
}

int xspd_stop_soap(xspdSoapContext *sc) {
	if (sc->soap) {
		soap_done(sc->soap);
		free(sc->soap);
	}
        return 0;
}
