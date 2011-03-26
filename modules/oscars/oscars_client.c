#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "oscars.h"
#include "oscarsH.h"

#include "wsseapi.h"
#include "threads.h"
#include "oscars.nsmap"

int main(int argc, char* argv[])
{
  int i, j;
  struct tm tm;

  char *response;

  xspdSoapContext oscars_soap;
  struct soap soap;
  
  soap_init(&soap);
  soap_set_omode(&soap, SOAP_XML_CANONICAL | SOAP_XML_INDENT | SOAP_IO_CHUNK);
  soap_set_namespaces(&soap, oscars_namespaces); 

  soap_register_plugin(&soap, soap_wsse);
  soap_ssl_init();

  if (soap_ssl_client_context(&soap,
  			      SOAP_SSL_NO_AUTHENTICATION, /* use SOAP_SSL_DEFAULT in production code */
  			      NULL,                       /* keyfile: required only when client must authenticate to 
  					                     server (see SSL docs on how to obtain this file) */
  			      NULL,                       /* password to read the keyfile */
  			      NULL,                       /* optional cacert file to store trusted certificates */
  			      NULL,                       /* optional capath to directory with trusted certificates */
  			      NULL                        /* if randfile!=NULL: use a file with random data to seed randomness */ 
  			      )) { 
     soap_print_fault(&soap, stderr);
     exit(1);
  }
  
  // SOAP context is ready to go
  oscars_soap.soap = &soap;
  oscars_soap.soap_endpoint = "https://localhost:8443/axis2/services/OSCARS";
  oscars_soap.soap_action = NULL;

  soap_wsse_add_Security(&soap);  

  FILE *fd;
  EVP_PKEY *rsa_private_key;

  fd = fopen("/home/ezra/.ssl/oscars-key.pem", "r");
  rsa_private_key = PEM_read_PrivateKey(fd, NULL, NULL, NULL);
  fclose(fd);
  fd = fopen("/home/ezra/.ssl/oscars-cert.pem", "r");
  X509 *cert = PEM_read_X509(fd, NULL, NULL, NULL);
  fclose(fd);

  soap_wsse_add_Timestamp(&soap, "Time", 600);

  if (soap_wsse_add_BinarySecurityTokenX509(&soap, "binaryToken", cert)
      || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(&soap, "#binaryToken")
      || soap_wsse_sign_body(&soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_private_key, 0)
      || soap_wsse_sign_only(&soap, "Body"))
      {
	  soap_print_fault(&soap, stderr);
	  exit(1);
      }

  printf("\nTesting oscars_cancelReservation\n\n");
  if (oscars_cancelReservation(&oscars_soap, "blah", &response) == 0)
      {
	  printf("Response: %s\n", response);
      }

  printf("done\n");

  soap_destroy(&soap);
  soap_end(&soap);

  return 0;
}

