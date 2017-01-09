#include "oscars.h"

void _oscars_pretty_print_path_info(void *path) {
  struct ns1__pathInfo *pi = (struct ns1__pathInfo*)path;

  if (!pi)
    return;

  printf("\t   setup mode: %s\n", pi->pathSetupMode);
  if (pi->pathType)
    printf("\t   path type: %s\n", pi->pathType);
  if (pi->path) {
    printf("\t   path content: N/A\n");
  }
  if (pi->layer2Info) {
    printf("\t   layer2Info:\n");
    printf("\t\tSRC: %s\n", pi->layer2Info->srcEndpoint);
    printf("\t\tDST: %s\n", pi->layer2Info->destEndpoint);
    if (pi->layer2Info->srcVtag)
      printf("\t\tSRC_vlan_id: %s, tagged = %d\n",
             pi->layer2Info->srcVtag->__item,
             pi->layer2Info->srcVtag->tagged);
    if (pi->layer2Info->destVtag)
      printf("\t\tDST_vlan_id: %s, tagged = %d\n",
             pi->layer2Info->destVtag->__item,
             pi->layer2Info->destVtag->tagged);
  }
  if (pi->layer3Info) {
    printf("\t   layer3Info:\n");
    printf("\t\tSRC: %s\n", pi->layer3Info->srcHost);
    printf("\t\tDST: %s\n", pi->layer3Info->destHost);
    if (pi->layer3Info->protocol)
      printf("\t\tprotocol: %s\n", pi->layer3Info->protocol);
    if (pi->layer3Info->srcIpPort)
      printf("\t\tsrc_port: %d\n", *(pi->layer3Info->srcIpPort));
    if (pi->layer3Info->destIpPort)
      printf("\t\tdst_port: %d\n", *(pi->layer3Info->destIpPort));
    if (pi->layer3Info->dscp)
      printf("\t\tDSCP: %s\n", pi->layer3Info->dscp);
  }
  if (pi->mplsInfo) {
    printf("\t   mplsInfo:\n");
    printf("\t\tburst limit: %d\n", pi->mplsInfo->burstLimit);
    if (pi->mplsInfo->lspClass)
      printf("\t\tLSP class: %s\n", pi->mplsInfo->lspClass);
  }
}

void oscars_pretty_print(int type, void *res) {
  switch (type) {

  case MODIFY_RES:
  case QUERY_RES: {
    struct ns1__resDetails *det = (struct ns1__resDetails*)res;
    char *stime, *etime, *crtime;

    stime = strdup(ctime((const time_t*)&det->userRequestConstraint->startTime));
    etime = strdup(ctime((const time_t*)&det->userRequestConstraint->endTime));
    crtime = strdup(ctime((const time_t*)&det->createTime));

    printf("GRI: %s\n", det->globalReservationId);
    printf("\t login: %s\n\t status: %s\n\t start:\t\t%s\t end:\t\t%s",
           det->login, det->status, stime, etime);
    printf("\t create:\t%s\t bandwidth: %d\n\t description: %s\n\t pathInfo:\n",
           crtime, det->userRequestConstraint->bandwidth, det->description);
    if (det->userRequestConstraint)
      _oscars_pretty_print_path_info((void*)det->userRequestConstraint->pathInfo);
    free(stime);
    free(etime);
    free(crtime);
  }
  break;
  case CREATE_RES: {
    struct ns1__createReply *tmp =
      (struct ns1__createReply*)res;
    printf("GRI: %s\n", tmp->globalReservationId);
    if (tmp->token)
      printf("\t token: %s\n", tmp->token);
    printf("\t status: %s\n", tmp->status);
    printf("\t pathInfo:\n");
    if (tmp->userRequestConstraint)
      _oscars_pretty_print_path_info((void*)tmp->userRequestConstraint->pathInfo);
  }
  break;
  case CANCEL_RES: {
    printf("GRI: %s\n", (char*)res);
  }
  break;
  case LIST_RES: {
    int i;
    struct ns1__listReply *tmp =
      (struct ns1__listReply*)res;
    printf("Total results: %d\n", *(tmp->totalResults));
    for (i=0; i<tmp->__sizeresDetails; i++) {
      struct ns1__resDetails *det = tmp->resDetails[i];
      char *stime, *etime, *crtime;

      stime = strdup(ctime((const time_t*)&det->userRequestConstraint->startTime));
      etime = strdup(ctime((const time_t*)&det->userRequestConstraint->endTime));
      crtime = strdup(ctime((const time_t*)&det->createTime));

      printf("[%d] GRI: %s\n", i, det->globalReservationId);
      printf("\t login: %s\n\t status: %s\n\t start:\t\t%s\t end:\t\t%s",
             det->login, det->status, stime, etime);
      printf("\t create:\t%s\t bandwidth: %d\n\t description: %s\n\t pathInfo:\n",
             crtime, det->userRequestConstraint->bandwidth, det->description);
      if (det->userRequestConstraint)
        _oscars_pretty_print_path_info((void*)det->userRequestConstraint->pathInfo);
      free(stime);
      free(etime);
      free(crtime);
    }
  }
  break;
  case GET_TOPO: {
    int i, j, k, l;
    struct ns5__CtrlPlaneTopologyContent *tmp =
      (struct ns5__CtrlPlaneTopologyContent*)res;

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

int _oscars_wsse_sign(xspSoapContext *osc) {
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

int oscars_getNetworkTopology(xspSoapContext *osc, const char *request, void **response) {
  int ret = 0;

  struct ns1__getTopologyContent nt_req;
  struct ns1__getTopologyResponseContent nt_res;

  bzero(&nt_req, sizeof(struct ns1__getTopologyContent));
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

      *response = nt_res.ns5__topology;

    }
    else {
      soap_print_fault((struct soap *)osc->soap, stderr);
      ret = -1;
    }
  }

  return ret;
}


int oscars_listReservations(xspSoapContext *osc, const OSCARS_listRequest *request, void **response) {
  int ret = 0;
  int i;

  struct ns1__listRequest list_req;
  struct ns1__listReply *list_res = calloc(1, sizeof(struct ns1__listReply));

  bzero(&list_req, sizeof(struct ns1__listRequest));

  OSCARS_listRequest *lr = (OSCARS_listRequest *)request;

  if (lr->description)
    list_req.description = lr->description;

  if (lr->res_requested)
    list_req.resRequested = &(lr->res_requested);

  if (lr->res_offset)
    list_req.resOffset = &(lr->res_offset);

  // Reservation statuses
  if (lr->size_status > 0 && lr->size_status <= 5) {
    list_req.__sizeresStatus = lr->size_status;
    for (i=0; i<lr->size_status; i++) {
      if (lr->statuses[i])
        list_req.resStatus[i] = lr->statuses[i];
      else
        return -1;
    }
  }

  // Reservation times
  if (lr->size_res_times > 0) {
    list_req.__size_listRequest_sequence = lr->size_res_times;
    if (!(lr->res_times))
      return -1;
    for (i=0; i<lr->size_res_times; i++) {
      if (lr->res_times[i]) {
        list_req.__listRequest_sequence->startTime =
          lr->res_times[i]->start_time;
        list_req.__listRequest_sequence->endTime =
          lr->res_times[i]->end_time;
      }
      else
        return -1;
    }
  }

  // Links
  if (lr->size_links > 0) {
    list_req.__sizelinkId = lr->size_links;
    for (i=0; i<lr->size_links; i++) {
      if (lr->links[i])
        list_req.linkId[i] = lr->links[i];
      else
        return -1;
    }
  }

  // VLANs
  if (lr->size_vlan_tags > 0) {
    list_req.__sizevlanTag = lr->size_vlan_tags;
    if (!(lr->vlan_tags))
      return -1;
    for (i=0; i<lr->size_vlan_tags; i++) {
      if (lr->vlan_tags[i]) {
        list_req.vlanTag[i]->__item =
          lr->vlan_tags[i]->id;
        list_req.vlanTag[i]->tagged =
          (enum xsd__boolean_)*(lr->vlan_tags[i]->tagged);
      }
      else
        return -1;
    }
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

int oscars_createReservation(xspSoapContext *osc, const OSCARS_resRequest *request, void **response) {
  int ret = 0;

  struct ns1__resCreateContent create_req;
  struct ns1__userRequestConstraintType user_content;
  struct ns1__createReply *create_res = calloc(1, sizeof(struct ns1__createReply));
  struct ns1__vlanTag src_tag, dst_tag;

  bzero(&create_req, sizeof(struct ns1__resCreateContent));
  bzero(&user_content, sizeof(struct ns1__userRequestConstraintType));
  bzero(&src_tag, sizeof(struct ns1__vlanTag));
  bzero(&dst_tag, sizeof(struct ns1__vlanTag));

  OSCARS_resRequest *cr = (OSCARS_resRequest *)request;

  src_tag.__item = cr->path_info->l2_info->src_vlan->id;
  if (cr->path_info->l2_info->src_vlan->tagged)
    src_tag.tagged = *(cr->path_info->l2_info->src_vlan->tagged);
  dst_tag.__item = cr->path_info->l2_info->dst_vlan->id;
  if (cr->path_info->l2_info->dst_vlan->tagged)
    dst_tag.tagged = *(cr->path_info->l2_info->dst_vlan->tagged);

  cr->path_info->l2_info->src_vlan = (OSCARS_vlanTag*)&src_tag;
  cr->path_info->l2_info->dst_vlan = (OSCARS_vlanTag*)&dst_tag;

  if (cr->res_id)
    create_req.globalReservationId = cr->res_id;

  user_content.startTime = cr->start_time;
  user_content.endTime = cr->end_time;
  user_content.bandwidth = cr->bandwidth;
  user_content.pathInfo = (struct ns1__pathInfo*)cr->path_info;

  create_req.description = cr->description;
  create_req.userRequestConstraint = &user_content;

  if (_oscars_wsse_sign(osc) != 0) {
    return -1;
  }

  if (soap_call___ns1__createReservation((struct soap*)osc->soap,
                                         osc->soap_endpoint,
                                         osc->soap_action,
                                         &create_req, create_res) == SOAP_OK) {
    *response = create_res;
  }
  else {
    soap_print_fault((struct soap *)osc->soap, stderr);
    free(create_res);
    ret = -1;
  }

  return ret;
}

int oscars_modifyReservation(xspSoapContext *osc, const OSCARS_resRequest *request, void **response) {
  int ret = 0;

  struct ns1__modifyResContent modify_req;
  struct ns1__userRequestConstraintType user_content;
  struct ns1__modifyResReply *modify_res = calloc(1, sizeof(struct ns1__modifyResReply));

  bzero(&modify_req, sizeof(struct ns1__modifyResContent));
  bzero(&user_content, sizeof(struct ns1__userRequestConstraintType));

  OSCARS_resRequest *cr = (OSCARS_resRequest *)request;

  if (cr->res_id)
    modify_req.globalReservationId = cr->res_id;

  user_content.startTime = cr->start_time;
  user_content.endTime = cr->end_time;
  user_content.bandwidth = cr->bandwidth;
  user_content.pathInfo = (struct ns1__pathInfo*)cr->path_info;

  modify_req.description = cr->description;
  modify_req.userRequestConstraint = &user_content;

  if (_oscars_wsse_sign(osc) != 0) {
    return -1;
  }

  if (soap_call___ns1__modifyReservation((struct soap*)osc->soap,
                                         osc->soap_endpoint,
                                         osc->soap_action,
                                         &modify_req, modify_res) == SOAP_OK) {

    *response = modify_res->reservation;
  }
  else {
    soap_print_fault((struct soap *)osc->soap, stderr);
    free(modify_res);
    ret = -1;
  }

  return ret;
}

int oscars_queryReservation(xspSoapContext *osc, const char *request, void **response) {
  int ret =0;

  struct ns1__queryResContent query_req;
  struct ns1__queryResReply query_res;

  bzero(&query_req, sizeof(struct ns1__queryResContent));

  if (_oscars_wsse_sign(osc) != 0) {
    return -1;
  }

  if (request) {
    query_req.globalReservationId = (char *) request;
    if (soap_call___ns1__queryReservation((struct soap*)osc->soap,
                                          osc->soap_endpoint,
                                          osc->soap_action,
                                          &query_req, &query_res) == SOAP_OK) {
      *response = query_res.reservationDetails;
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

int oscars_cancelReservation(xspSoapContext *osc, const char *request, void **response) {
  int ret = 0;

  struct ns1__cancelResContent cancel_req;
  struct ns1__cancelResReply cancel_res;

  bzero(&cancel_req, sizeof(struct ns1__cancelResContent));

  if (_oscars_wsse_sign(osc) != 0) {
    return -1;
  }

  if (request) {
    cancel_req.globalReservationId = (char *) request;
    if (soap_call___ns1__cancelReservation((struct soap*)osc->soap,
                                           osc->soap_endpoint,
                                           osc->soap_action,
                                           &cancel_req, &cancel_res) == SOAP_OK) {
      if (cancel_res.status)
        *response = cancel_res.status;
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
