#include "monitoring.h"
#include "mntrH.h"

int monitoring_notify(xspdSoapContext *mntr, const char *id, const char *src, 
		      const char *dst,const char *src_port_range, const char *dst_port_range,
                      const char *vlan_id, const char *direction, uint64_t start_time, 
		      uint64_t duration, uint64_t bw, const char *bw_class, const char* status)
{
  struct ns1__new_USCOREpath path_req;
  struct ns1__new_USCOREpathResponse path_res;
  struct ns1__PathData pathdata;
  
  bzero(&path_req, sizeof(struct ns1__new_USCOREpath));
  bzero(&path_res, sizeof(struct ns1__new_USCOREpathResponse));
  bzero(&pathdata, sizeof(struct ns1__PathData));

  pathdata.bandwidth = (int*)&bw;
  pathdata.start_USCOREtime = (int*)&start_time;
  pathdata.duration = (int*)&duration;
  pathdata.direction = (char*)direction;  

  if (src)
    pathdata.src = (char*)src;
  if (dst)
    pathdata.dst = (char*)dst;
  if (src_port_range)
    pathdata.src_USCOREport_USCORErange = (char*)src_port_range;
  if (dst_port_range)
    pathdata.dst_USCOREport_USCORErange = (char*)dst_port_range;
  if(vlan_id)
    pathdata.vlan_USCOREid = (char *)vlan_id;
  if(id)
    pathdata.path_USCOREid = (char *)id;
  if(bw_class)
    pathdata.bw_USCOREclass = (char *)bw_class;
  if (status)
    pathdata.status = (char*)status;

  path_req.newpath = &pathdata;

  if(soap_call___ns1__new_USCOREpath((struct soap *)mntr->soap,
				     mntr->soap_endpoint,
				     mntr->soap_action,
				     &path_req,
				     &path_res
				     )== SOAP_OK)    
    {
      if(path_res.new_USCOREpathResult)
	{
	}
      else
	      return -1;
    }
  else 
    {
      soap_print_fault((struct soap *)mntr->soap, stderr);
      soap_print_fault_location((struct soap *)mntr->soap, stderr);
      return -1;
    } 
  
  return 0;
}

int monitoring_remove(xspdSoapContext *mntr, const char *res_id) 
{
  struct ns1__remove_USCOREpath remove_req;
  struct ns1__remove_USCOREpathResponse remove_res;

  bzero(&remove_req, sizeof(struct ns1__remove_USCOREpath));
  bzero(&remove_res, sizeof(struct ns1__remove_USCOREpathResponse));

  if (res_id)
    remove_req.pathid = (char*)res_id;
  else
	  return -1;
  
  if (soap_call___ns1__remove_USCOREpath((struct soap *)mntr->soap, 
					 mntr->soap_endpoint, 
					 mntr->soap_action,
					 &remove_req, &remove_res
					 ) == SOAP_OK)
    {
      if (!(remove_res.remove_USCOREpathResult))
	      return -1;
    }
  else
    {
      soap_print_fault((struct soap *)mntr->soap, stderr);
      return -1;
    }
  return 0;
}


int monitoring_set_status(xspdSoapContext *mntr, const char *res_id, const char *status) 
{
  struct ns1__status_USCOREpath status_req;
  struct ns1__status_USCOREpathResponse status_res;
  struct ns1__PathData pathdata;

  bzero(&status_req, sizeof(struct ns1__status_USCOREpath));
  bzero(&status_res, sizeof(struct ns1__status_USCOREpathResponse));
  bzero(&pathdata, sizeof(struct ns1__PathData));

  if (res_id)
    pathdata.path_USCOREid = (char*)res_id;
  else
    return -1;
  
  if (status)
    pathdata.status = (char*)status;
  
  status_req.path = &pathdata;

  if (soap_call___ns1__status_USCOREpath((struct soap *)mntr->soap, 
					 mntr->soap_endpoint, 
					 mntr->soap_action,
					 &status_req, &status_res
					 ) == SOAP_OK)
    {
      if (!(status_res.status_USCOREpathResult))
	      return -1;
    }
  else
    {
      soap_print_fault((struct soap *)mntr->soap, stderr);
      return -1;
    }
  return 0;
}

int monitoring_update_path(xspdSoapContext *mntr, const char *res_id, const char *src,
			   const char *dst, const char *src_port_range, const char *dst_port_range,
			   const char *vlan_id, const char *direction, uint64_t start_time,
			   uint64_t duration, uint64_t bw, const char *bw_class, const char *status)
{
	struct ns1__status_USCOREpath status_req;
	struct ns1__status_USCOREpathResponse status_res;
	struct ns1__PathData pathdata;

	bzero(&status_req, sizeof(struct ns1__status_USCOREpath));
	bzero(&status_res, sizeof(struct ns1__status_USCOREpathResponse));
	bzero(&pathdata, sizeof(struct ns1__PathData));

	if (res_id)
		pathdata.path_USCOREid = (char*)res_id;
	else
		return -1;

	pathdata.bandwidth = (int*)&bw;
	pathdata.start_USCOREtime = (int*)&start_time;
	pathdata.duration = (int*)&duration;

	if (status)
		pathdata.status = (char*)status;
	if (src)
		pathdata.src = (char*)src;
	if (dst)
		pathdata.dst = (char*)dst;
	if (src_port_range)
		pathdata.src_USCOREport_USCORErange = (char*)src_port_range;
	if (dst_port_range)
		pathdata.dst_USCOREport_USCORErange = (char*)dst_port_range;
	if (vlan_id)
		pathdata.vlan_USCOREid = (char *)vlan_id;
	if (bw_class)
		pathdata.bw_USCOREclass = (char *)bw_class;
	if (direction)
		pathdata.direction = (char *)direction;

	status_req.path = &pathdata;

	if (soap_call___ns1__status_USCOREpath((struct soap *)mntr->soap,
					       mntr->soap_endpoint,
					       mntr->soap_action,
					       &status_req, &status_res
					       ) == SOAP_OK)
		{
			if (!(status_res.status_USCOREpathResult))
				return -1;
		}
	else
		{
			soap_print_fault((struct soap *)mntr->soap, stderr);
			return -1;
		}
	return 0;
}
