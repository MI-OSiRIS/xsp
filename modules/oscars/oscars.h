#ifndef OSCARS_H
#define OSCARS_H

#include <stdint.h>
#include "xspd_soap_context.h"
#include "threads.h"
#include "wsseapi.h"

int oscars_cancelReservation(xspdSoapContext *osc, const char *gri, char **res);


#endif
