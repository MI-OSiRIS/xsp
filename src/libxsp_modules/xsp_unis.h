#ifndef XSP_UNIS_H
#define XSP_UNIS_H

#define XSP_UNIS_REFRESH_TO   60
#define XSP_UNIS_REG_INTERVAL 720

typedef struct xsp_unis_config_t {
	char *endpoint;
	int do_register;
	int registration_interval;
	int refresh_timer;
} xspUNISConfig;

/* public methods */

/* 
   first param is the service name we're looking for
   sets a list of service access points for the caller
*/
int xsp_unis_get_service_access_points(char *sname, char ***ret_aps, int *num_aps);

/* ... and we need to think about the list of query methods
   the more general we can make these the better, the above is just a test */

#endif
