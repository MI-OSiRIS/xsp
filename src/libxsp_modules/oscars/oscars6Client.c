/* oscars6Client.c
   Generated by gSOAP 2.8.1 from oscars6API.h
   Copyright(C) 2000-2010, Robert van Engelen, Genivia Inc. All Rights Reserved.
   The generated code is released under one of the following licenses:
   GPL OR Genivia's license for commercial use.
*/

#if defined(__BORLANDC__)
#pragma option push -w-8060
#pragma option push -w-8004
#endif
#include "oscars6H.h"
#ifdef __cplusplus
extern "C" {
#endif

SOAP_SOURCE_STAMP("@(#) oscars6Client.c ver 2.8.1 2011-04-10 17:09:09 GMT")


SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__createReservation(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__resCreateContent *ns1__createReservation, struct ns1__createReply *ns1__createReservationResponse) {
  struct __ns1__createReservation soap_tmp___ns1__createReservation;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/createReservation";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__createReservation.ns1__createReservation = ns1__createReservation;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__createReservation(soap, &soap_tmp___ns1__createReservation);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__createReservation(soap, &soap_tmp___ns1__createReservation, "-ns1:createReservation", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__createReservation(soap, &soap_tmp___ns1__createReservation, "-ns1:createReservation", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__createReservationResponse)
    return soap_closesock(soap);
  soap_default_ns1__createReply(soap, ns1__createReservationResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__createReply(soap, ns1__createReservationResponse, "ns1:createReservationResponse", "ns1:createReply");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__queryReservation(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__queryResContent *ns1__queryReservation, struct ns1__queryResReply *ns1__queryReservationResponse) {
  struct __ns1__queryReservation soap_tmp___ns1__queryReservation;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/queryReservation";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__queryReservation.ns1__queryReservation = ns1__queryReservation;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__queryReservation(soap, &soap_tmp___ns1__queryReservation);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__queryReservation(soap, &soap_tmp___ns1__queryReservation, "-ns1:queryReservation", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__queryReservation(soap, &soap_tmp___ns1__queryReservation, "-ns1:queryReservation", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__queryReservationResponse)
    return soap_closesock(soap);
  soap_default_ns1__queryResReply(soap, ns1__queryReservationResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__queryResReply(soap, ns1__queryReservationResponse, "ns1:queryReservationResponse", "ns1:queryResReply");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__listReservations(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__listRequest *ns1__listReservations, struct ns1__listReply *ns1__listReservationsResponse) {
  struct __ns1__listReservations soap_tmp___ns1__listReservations;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/listReservations";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__listReservations.ns1__listReservations = ns1__listReservations;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__listReservations(soap, &soap_tmp___ns1__listReservations);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__listReservations(soap, &soap_tmp___ns1__listReservations, "-ns1:listReservations", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__listReservations(soap, &soap_tmp___ns1__listReservations, "-ns1:listReservations", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__listReservationsResponse)
    return soap_closesock(soap);
  soap_default_ns1__listReply(soap, ns1__listReservationsResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__listReply(soap, ns1__listReservationsResponse, "ns1:listReservationsResponse", "ns1:listReply");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__cancelReservation(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__cancelResContent *ns1__cancelReservation, struct ns1__cancelResReply *ns1__cancelReservationResponse) {
  struct __ns1__cancelReservation soap_tmp___ns1__cancelReservation;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/cancelReservation";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__cancelReservation.ns1__cancelReservation = ns1__cancelReservation;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__cancelReservation(soap, &soap_tmp___ns1__cancelReservation);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__cancelReservation(soap, &soap_tmp___ns1__cancelReservation, "-ns1:cancelReservation", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__cancelReservation(soap, &soap_tmp___ns1__cancelReservation, "-ns1:cancelReservation", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__cancelReservationResponse)
    return soap_closesock(soap);
  soap_default_ns1__cancelResReply(soap, ns1__cancelReservationResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__cancelResReply(soap, ns1__cancelReservationResponse, "ns1:cancelReservationResponse", "ns1:cancelResReply");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__modifyReservation(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__modifyResContent *ns1__modifyReservation, struct ns1__modifyResReply *ns1__modifyReservationResponse) {
  struct __ns1__modifyReservation soap_tmp___ns1__modifyReservation;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/modifyReservation";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__modifyReservation.ns1__modifyReservation = ns1__modifyReservation;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__modifyReservation(soap, &soap_tmp___ns1__modifyReservation);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__modifyReservation(soap, &soap_tmp___ns1__modifyReservation, "-ns1:modifyReservation", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__modifyReservation(soap, &soap_tmp___ns1__modifyReservation, "-ns1:modifyReservation", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__modifyReservationResponse)
    return soap_closesock(soap);
  soap_default_ns1__modifyResReply(soap, ns1__modifyReservationResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__modifyResReply(soap, ns1__modifyReservationResponse, "ns1:modifyReservationResponse", "ns1:modifyResReply");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__getNetworkTopology(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__getTopologyContent *ns1__getNetworkTopology, struct ns1__getTopologyResponseContent *ns1__getNetworkTopologyResponse) {
  struct __ns1__getNetworkTopology soap_tmp___ns1__getNetworkTopology;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/getNetworkTopology";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__getNetworkTopology.ns1__getNetworkTopology = ns1__getNetworkTopology;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__getNetworkTopology(soap, &soap_tmp___ns1__getNetworkTopology);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__getNetworkTopology(soap, &soap_tmp___ns1__getNetworkTopology, "-ns1:getNetworkTopology", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__getNetworkTopology(soap, &soap_tmp___ns1__getNetworkTopology, "-ns1:getNetworkTopology", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__getNetworkTopologyResponse)
    return soap_closesock(soap);
  soap_default_ns1__getTopologyResponseContent(soap, ns1__getNetworkTopologyResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__getTopologyResponseContent(soap, ns1__getNetworkTopologyResponse, "ns1:getNetworkTopologyResponse", "ns1:getTopologyResponseContent");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__createPath(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__createPathContent *ns1__createPath, struct ns1__createPathResponseContent *ns1__createPathResponse) {
  struct __ns1__createPath soap_tmp___ns1__createPath;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/createPath";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__createPath.ns1__createPath = ns1__createPath;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__createPath(soap, &soap_tmp___ns1__createPath);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__createPath(soap, &soap_tmp___ns1__createPath, "-ns1:createPath", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__createPath(soap, &soap_tmp___ns1__createPath, "-ns1:createPath", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__createPathResponse)
    return soap_closesock(soap);
  soap_default_ns1__createPathResponseContent(soap, ns1__createPathResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__createPathResponseContent(soap, ns1__createPathResponse, "ns1:createPathResponse", "ns1:createPathResponseContent");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__refreshPath(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__refreshPathContent *ns1__refreshPath, struct ns1__refreshPathResponseContent *ns1__refreshPathResponse) {
  struct __ns1__refreshPath soap_tmp___ns1__refreshPath;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/refreshPath";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__refreshPath.ns1__refreshPath = ns1__refreshPath;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__refreshPath(soap, &soap_tmp___ns1__refreshPath);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__refreshPath(soap, &soap_tmp___ns1__refreshPath, "-ns1:refreshPath", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__refreshPath(soap, &soap_tmp___ns1__refreshPath, "-ns1:refreshPath", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__refreshPathResponse)
    return soap_closesock(soap);
  soap_default_ns1__refreshPathResponseContent(soap, ns1__refreshPathResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__refreshPathResponseContent(soap, ns1__refreshPathResponse, "ns1:refreshPathResponse", "ns1:refreshPathResponseContent");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_call___ns1__teardownPath(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__teardownPathContent *ns1__teardownPath, struct ns1__teardownPathResponseContent *ns1__teardownPathResponse) {
  struct __ns1__teardownPath soap_tmp___ns1__teardownPath;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/teardownPath";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__teardownPath.ns1__teardownPath = ns1__teardownPath;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__teardownPath(soap, &soap_tmp___ns1__teardownPath);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__teardownPath(soap, &soap_tmp___ns1__teardownPath, "-ns1:teardownPath", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__teardownPath(soap, &soap_tmp___ns1__teardownPath, "-ns1:teardownPath", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  if (!ns1__teardownPathResponse)
    return soap_closesock(soap);
  soap_default_ns1__teardownPathResponseContent(soap, ns1__teardownPathResponse);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get_ns1__teardownPathResponseContent(soap, ns1__teardownPathResponse, "ns1:teardownPathResponse", "ns1:teardownPathResponseContent");
  if (soap->error)
    return soap_recv_fault(soap, 0);
  if (soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

SOAP_FMAC5 int SOAP_FMAC6 soap_send___ns1__interDomainEvent(struct soap *soap, const char *soap_endpoint, const char *soap_action, struct ns1__interDomainEventContent *ns1__interDomainEvent) {
  struct __ns1__interDomainEvent soap_tmp___ns1__interDomainEvent;
  if (!soap_endpoint)
    soap_endpoint = "http://192.168.1.20:9001/OSCARS";
  if (!soap_action)
    soap_action = "http://oscars.es.net/OSCARS/interDomainEvent";
  soap->encodingStyle = NULL;
  soap_tmp___ns1__interDomainEvent.ns1__interDomainEvent = ns1__interDomainEvent;
  soap_begin(soap);
  soap_serializeheader(soap);
  soap_serialize___ns1__interDomainEvent(soap, &soap_tmp___ns1__interDomainEvent);
  if (soap_begin_count(soap))
    return soap->error;
  if (soap->mode & SOAP_IO_LENGTH) {
    if (soap_envelope_begin_out(soap)
        || soap_putheader(soap)
        || soap_body_begin_out(soap)
        || soap_put___ns1__interDomainEvent(soap, &soap_tmp___ns1__interDomainEvent, "-ns1:interDomainEvent", NULL)
        || soap_body_end_out(soap)
        || soap_envelope_end_out(soap))
      return soap->error;
  }
  if (soap_end_count(soap))
    return soap->error;
  if (soap_connect(soap, soap_endpoint, soap_action)
      || soap_envelope_begin_out(soap)
      || soap_putheader(soap)
      || soap_body_begin_out(soap)
      || soap_put___ns1__interDomainEvent(soap, &soap_tmp___ns1__interDomainEvent, "-ns1:interDomainEvent", NULL)
      || soap_body_end_out(soap)
      || soap_envelope_end_out(soap)
      || soap_end_send(soap))
    return soap_closesock(soap);
  return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 soap_recv___ns1__interDomainEvent(struct soap *soap, struct __ns1__interDomainEvent *_param_1) {
  soap_default___ns1__interDomainEvent(soap, _param_1);
  soap_begin(soap);
  if (soap_begin_recv(soap)
      || soap_envelope_begin_in(soap)
      || soap_recv_header(soap)
      || soap_body_begin_in(soap))
    return soap_closesock(soap);
  soap_get___ns1__interDomainEvent(soap, _param_1, "-ns1:interDomainEvent", NULL);
  if (soap->error == SOAP_TAG_MISMATCH && soap->level == 2)
    soap->error = SOAP_NO_METHOD;
  if (soap->error
      || soap_body_end_in(soap)
      || soap_envelope_end_in(soap)
      || soap_end_recv(soap))
    return soap_closesock(soap);
  return soap_closesock(soap);
}

#ifdef __cplusplus
}
#endif

#if defined(__BORLANDC__)
#pragma option pop
#pragma option pop
#endif

/* End of oscars6Client.c */
