#ifndef LSD_ROUTE_H
#define LSD_ROUTE_H

/*
 *  int libxsp_wrapper_route_init():
 *      This function initializes the routing structure
 */
int libxsp_wrapper_route_init();

/*
 *  const char *libxsp_wrapper_route_lookup(char *hop_id):
 *      This function looks up if a better route is known for the specified
 *      hop
 */
const struct libxsp_route_path_info *libxsp_wrapper_route_lookup(const char *hop_id);

/*
 *  int libxsp_wrapper_route_read(const char *filename):
 *      This function reads in a list of addr/masks and hops and replaces its
 *      current route structure with the one specified in the file.
 */
int libxsp_wrapper_route_read(const char *filename);

/*
 *  int libxsp_wrapper_route_add(char *addr_mask, char *hop_id):
 *      This function adds a route to the route structure
 */
int libxsp_wrapper_route_add(const char *addr_mask, const char **path, int path_count, const int *ports, int port_count);

/*
 *  int libxsp_wrapper_route_remove(char *addr_mask):
 *      This function removes a route from the route structure
 */
int libxsp_wrapper_route_remove(const char *addr_mask);

struct libxsp_route_path_info {
	int *ports;
	int port_count;

	char **path;
	int path_count;
};

const struct libxsp_route_path_info *libxsp_wrapper_route_lookup_sa(const struct sockaddr *sa);

#endif
