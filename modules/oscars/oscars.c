#include "oscars.h"
#include "oscarsH.h"

int oscars_listReservations(xspdSoapContext *osc)
{
    int ret = 0;

    struct ns1__listRequest list_req;
    struct ns1__listReply list_res;

    bzero(&list_req, sizeof(struct ns1__listRequest));
    bzero(&list_res, sizeof(struct ns1__listReply));

    if (soap_call___ns1__listReservations((struct soap*)osc->soap, osc->soap_endpoint, osc->soap_action,
					  &list_req, &list_res) == SOAP_OK)
	{
	}

    return ret;
}

int oscars_cancelReservation(xspdSoapContext *osc, const char *gri, char **res)
{
    int ret = 0;

    struct ns1__globalReservationId cancel_req;
    char *cancel_res;
    
    if (gri)
	{
	    cancel_req.gri = (char *) gri;
	    if (soap_call___ns1__cancelReservation((struct soap*)osc->soap, osc->soap_endpoint, osc->soap_action,
						  &cancel_req, &cancel_res) == SOAP_OK)
		{
		    if (cancel_res)
			*res = strdup(cancel_res);
		    else
			ret = -1;
		}
	    else
		{
		    soap_print_fault((struct soap *)osc->soap, stderr);
		    ret = -1;
		}
	}
    else
	ret = -1;

    return ret;
}
