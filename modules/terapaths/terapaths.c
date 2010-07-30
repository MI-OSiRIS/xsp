#include "terapaths.h"
#include "tpsH.h"

void __fill_reservation_data(struct ns2__ReservationData *res_data)
{
  struct ns2__Bandwidth *bw_data;
  struct ns2__Who *who_data;

  bw_data = (struct ns2__Bandwidth *)malloc(sizeof(struct ns2__Bandwidth));
  who_data = (struct ns2__Who *)malloc(sizeof(struct ns2__Who));
  
  bzero(res_data, sizeof(struct ns2__ReservationData));
  bzero(bw_data, sizeof(struct ns2__Bandwidth));
  bzero(who_data, sizeof(struct ns2__Who));

  who_data->CA = "";
  who_data->DN = "";
  who_data->name = "";
  res_data->who = who_data;
  
  bw_data->className = "";
  bw_data->bandwidth = 0;
  res_data->bandwidth = bw_data;

  res_data->startTime = -1;
  res_data->duration = -1;
  res_data->timeout = -1;
  res_data->DTMinus = 0;
  res_data->DTPlus = 0;
  res_data->startTimeMin = -1;
  res_data->startTimeMax = -1;
  res_data->modifyReservation = 0;
  res_data->direction = "";
  res_data->mapping = "";
  res_data->destIp = "";
  res_data->destPorts = "";
  res_data->destMapping = "";
  res_data->destName = "";
  res_data->destPortMax = "";
  res_data->destPortMin = "";
  res_data->id = "";
  res_data->protocol = "tcp";
  res_data->relatedReservationIds = "";
  res_data->srcMapping = "";
  res_data->userName = "";
  res_data->status = "";
  res_data->srcName = "";
  res_data->srcIp = "";
  res_data->srcPorts = "";
  res_data->srcPortMax = "";
  res_data->srcPortMin = "";  
}

int terapaths_reserve(xspdSoapContext *tsc, const char *src, const char *dst,
                      const char *src_ports, const char *dst_ports,
                      const char *direction, const char *bw_class, uint64_t bw,
                      uint64_t start_time, uint64_t duration, char **res_id) 
{
  int ret = 0;
  
  struct ns2__tpsAPI_USCOREreserve reserve_req;
  struct ns2__tpsAPI_USCOREreserveResponse reserve_res;
  struct ns2__ReservationData reserve_data;

  bzero(&reserve_req, sizeof(struct ns2__tpsAPI_USCOREreserve));
  bzero(&reserve_res, sizeof(struct ns2__tpsAPI_USCOREreserveResponse));
  
  __fill_reservation_data(&reserve_data);
  
  if (bw_class)
    reserve_data.bandwidth->className = (char*)bw_class;
  
  reserve_data.bandwidth->bandwidth = bw;
  reserve_data.startTime = start_time;
  reserve_data.startTimeMin = start_time;
  reserve_data.startTimeMax = start_time;
  reserve_data.duration = duration;
  reserve_data.direction = (char*)direction;  

  //some extras that are apparently constrained
  reserve_data.mapping = "strict";
  reserve_data.srcMapping = "strict";
  reserve_data.destMapping = "strict";
  
  if (src)
    reserve_data.srcIp = (char*)src;
  if (dst)
    reserve_data.destIp = (char*)dst;
  if (src_ports)
    reserve_data.srcPorts = (char*)src_ports;
  if (dst_ports)
    reserve_data.destPorts = (char*)dst_ports;
  
  reserve_req.ReservationData_USCORE1 = &reserve_data;

  if (soap_call___ns1__tpsAPI_USCOREreserve((struct soap *)tsc->soap, tsc->soap_endpoint, tsc->soap_action,
                                            &reserve_req, &reserve_res) == SOAP_OK)
    {
      if (reserve_res.result)
        *res_id = strdup(reserve_res.result->id);
      else
        ret = -1;
    }
  else
    {
      soap_print_fault((struct soap *)tsc->soap, stderr);
      ret = -1;
    }
  
  if (reserve_data.bandwidth)
    free(reserve_data.bandwidth);
  if (reserve_data.who)
    free(reserve_data.who);
  return ret;
}

int terapaths_commit(xspdSoapContext *tsc, const char *res_id) 
{
  int ret = 0;

  struct ns2__tpsAPI_USCOREcommit commit_req;
  struct ns2__tpsAPI_USCOREcommitResponse commit_res;
  struct ns2__ReservationData reserve_data;

  bzero(&commit_req, sizeof(struct ns2__tpsAPI_USCOREcommit));
  bzero(&commit_res, sizeof(struct ns2__tpsAPI_USCOREcommitResponse));

  __fill_reservation_data(&reserve_data);
  
  if (res_id)
    reserve_data.id = (char*)res_id;
  else
    {
      ret = -1;
      goto error_exit;
    }
  
  commit_req.ReservationData_USCORE1 = &reserve_data;
  
  if (soap_call___ns1__tpsAPI_USCOREcommit((struct soap *)tsc->soap, tsc->soap_endpoint, tsc->soap_action,
                                           &commit_req, &commit_res) == SOAP_OK)
    {
      if (!(commit_res.result))
        {
          ret = -1;
          goto error_exit;
        }
    }
  else
    {
      soap_print_fault((struct soap *)tsc->soap, stderr);
      ret = -1;
    }
  
 error_exit:
  if (reserve_data.bandwidth)
    free(reserve_data.bandwidth);
  if (reserve_data.who)
    free(reserve_data.who);
  return ret;
}

int terapaths_cancel(xspdSoapContext *tsc, const char *res_id) 
{
  int ret = 0;
  
  struct ns2__tpsAPI_USCOREcancel cancel_req;
  struct ns2__tpsAPI_USCOREcancelResponse cancel_res;
  struct ns2__ReservationData reserve_data;

  bzero(&cancel_req, sizeof(struct ns2__tpsAPI_USCOREcancel));
  bzero(&cancel_res, sizeof(struct ns2__tpsAPI_USCOREcancelResponse));

  __fill_reservation_data(&reserve_data);

  if (res_id)
    reserve_data.id = (char*)res_id;
  else
    {
      ret = -1;
      goto error_exit;
    }

  cancel_req.ReservationData_USCORE1 = &reserve_data;

  if (soap_call___ns1__tpsAPI_USCOREcancel((struct soap *)tsc->soap, tsc->soap_endpoint, tsc->soap_action,
                                           &cancel_req, &cancel_res) == SOAP_OK)
    {
      if (!(cancel_res.result))
        {
          ret = -1;
          goto error_exit;
        }
    }
  else
    {
      soap_print_fault((struct soap *)tsc->soap, stderr);
      ret = -1;
    }
  
 error_exit:
  if (reserve_data.bandwidth)
    free(reserve_data.bandwidth);
  if (reserve_data.who)
    free(reserve_data.who);
  return ret;
}

int terapaths_get_bandwidths(xspdSoapContext *tsc, const char *src, const char *dst, tpsBandwidths *res_result) 
{
  int i, j, size, bw_size;
  struct ns2__tpsAPI_USCOREgetBandwidths getBW_req;
  struct ns2__tpsAPI_USCOREgetBandwidthsResponse getBW_res;
  struct ns2__Bandwidths *result;
  
  bzero(&getBW_req, sizeof(struct ns2__tpsAPI_USCOREgetBandwidths));
  bzero(&getBW_res, sizeof(struct ns2__tpsAPI_USCOREgetBandwidthsResponse));
  
  getBW_req.String_USCORE1 = (char*)src;
  getBW_req.String_USCORE2 = (char*)dst;
  
  if (soap_call___ns1__tpsAPI_USCOREgetBandwidths((struct soap *)tsc->soap, tsc->soap_endpoint, 
                                                  tsc->soap_action, &getBW_req, &getBW_res) == SOAP_OK)
    {
      size = getBW_res.__sizeresult;
      res_result->size = size;
      res_result->bws = (tpsBandwidth **)malloc(size*sizeof(tpsBandwidth *));
      for (i=0; i < size; i++)
        { 
          if (getBW_res.result[i])
            {
              res_result->bws[i] = (tpsBandwidth *)malloc(sizeof(tpsBandwidth));
              result = getBW_res.result[i];
              bw_size = result->__sizebw;
              res_result->bws[i]->size = bw_size;
              
              (res_result->bws[i])->class = (char **)malloc(bw_size*sizeof(char *));
              (res_result->bws[i])->bw = (uint64_t *)malloc(bw_size*sizeof(uint64_t));
              
              for (j=0; j < bw_size; j++) {
                res_result->bws[i]->class[j] = strdup(result->bw[j]->className);
                res_result->bws[i]->bw[j] = result->bw[j]->bandwidth;
              }
            }
          else
            res_result->bws[i] = NULL;
        }
    }
  else
    {
      soap_print_fault((struct soap *)tsc->soap, stderr);
      return -1;
    }
  return 0;
}

int terapaths_get_path(xspdSoapContext *tsc, const char *src, const char *dst, tpsPath *res_result) 
{
  int i, size;
  struct ns2__tpsAPI_USCOREgetPath getPath_req;
  struct ns2__tpsAPI_USCOREgetPathResponse getPath_res;
  
  bzero(&getPath_req, sizeof(struct ns2__tpsAPI_USCOREgetPath));
  bzero(&getPath_res, sizeof(struct ns2__tpsAPI_USCOREgetPathResponse));
  
  getPath_req.String_USCORE1 = (char*)src;
  getPath_req.String_USCORE2 = (char*)dst;
  
  if (soap_call___ns1__tpsAPI_USCOREgetPath((struct soap *)tsc->soap, tsc->soap_endpoint, tsc->soap_action,
                                            &getPath_req, &getPath_res) == SOAP_OK) 
    {
      size = getPath_res.__sizeresult;
      res_result->path = (char **)malloc(size * sizeof(char *));
      for (i=0; i < size; i++) 
        {
          if (getPath_res.result[i])
            {
              res_result->path[i] = strdup(getPath_res.result[i]);
              res_result->size++;
            }
        }
    }
  else 
	  {
		  soap_print_fault((struct soap *)tsc->soap, stderr);
		  return -1;
	  }
  return 0;
}

int terapaths_get_related_ids(xspdSoapContext *tsc, const char *res_id, char **rel_ids)
{
  struct ns2__tpsAPI_USCOREgetRelatedReservationIds related_req;
  struct ns2__tpsAPI_USCOREgetRelatedReservationIdsResponse related_res;
  
  bzero(&related_req, sizeof(struct ns2__tpsAPI_USCOREgetRelatedReservationIds));
  bzero(&related_res, sizeof(struct ns2__tpsAPI_USCOREgetRelatedReservationIdsResponse));
  
  if (res_id)
    related_req.String_USCORE1 = (char *)res_id;
  else
    return -1;
  
  if (soap_call___ns1__tpsAPI_USCOREgetRelatedReservationIds((struct soap *)tsc->soap, tsc->soap_endpoint,
							     tsc->soap_action, &related_req,
							     &related_res) == SOAP_OK)
    {
      if (related_res.result)
	*rel_ids = strdup(related_res.result);
      else
	return -1;
    }
  else
    {
      soap_print_fault((struct soap *)tsc->soap, stderr);
      return -1;
    }
  
  return 0;
}

int terapaths_get_reservation_status(xspdSoapContext *tsc, const char *res_id, char **status)
{
  struct ns2__tpsAPI_USCOREgetReservationData reserve_req;
  struct ns2__tpsAPI_USCOREgetReservationDataResponse reserve_res;
  
  bzero(&reserve_req, sizeof(struct ns2__tpsAPI_USCOREgetReservationData));
  bzero(&reserve_res, sizeof(struct ns2__tpsAPI_USCOREgetReservationDataResponse));
  
  if (res_id)
    reserve_req.String_USCORE1 = (char *)res_id;
  else
    return -1;
  
  if (soap_call___ns1__tpsAPI_USCOREgetReservationData((struct soap *)tsc->soap, tsc->soap_endpoint,
							     tsc->soap_action, &reserve_req,
							     &reserve_res) == SOAP_OK)
    {
      if (reserve_res.result)
	*status = strdup(reserve_res.result->status);
      else
	return -1;     
    }
  else
    {
      soap_print_fault((struct soap *)tsc->soap, stderr);
      return -1;
    }

  return 0;
}
