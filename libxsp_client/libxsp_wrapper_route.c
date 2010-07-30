#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>

#include "compat.h"

#include "radix.h"
#include "libxsp.h"
#include "libxsp_wrapper_route.h"

radix_tree_t *routes = NULL;
pthread_mutex_t routes_lock;

static void libxsp_wrapper_free_path_info(void *v);
static int libxsp_wrapper_parse_route_line(char *buf, char **ret_addr_mask, char ***ret_path, int *ret_path_count, int **ret_ports, int *ret_port_count);
static int __libxsp_wrapper_route_add(radix_tree_t *route_tree, const char *addr_mask, const char **path, int path_count, const int *ports, int port_count);
static int __libxsp_wrapper_route_remove(radix_tree_t *tree, const char *addr_mask);

int libxsp_wrapper_route_init() {

	if(pthread_mutex_init(&routes_lock, 0) != 0) { 
		d_printf("libxsp_wrapper_route_init(): pthread_mutex_init failed\n");
		goto error_out;
	}

	routes = New_Radix(32);
	if (!routes) {
		d_printf("libxsp_wrapper_route_init(): New_Radix failed\n");
		goto error_out2;
	}

	return 0;

error_out2:
	pthread_mutex_destroy(&routes_lock);
error_out:
	return -1;
}

int libxsp_wrapper_route_add(const char *addr_mask, const char **path, int path_count, const int *ports, int port_count) {
	int retval;

	pthread_mutex_lock(&routes_lock);
	{
		retval = __libxsp_wrapper_route_add(routes, addr_mask, path, path_count, ports, port_count);
	}
	pthread_mutex_unlock(&routes_lock);

	return retval;
}

int libxsp_wrapper_route_remove(const char *addr_mask) {
	int retval;

	pthread_mutex_lock(&routes_lock);
	{
		retval = __libxsp_wrapper_route_remove(routes, addr_mask);
	}
	pthread_mutex_unlock(&routes_lock);

	return retval;
}

int libxsp_wrapper_route_read(const char *filename) {
	FILE *f;
	char line[1024];
	int linelen;

	radix_tree_t *new_routes, *old_routes;

	/* initialize new route table */

	if (!filename)
		return -1;

	new_routes = New_Radix(32);

	f = fopen(filename, "r");
	if (f == NULL) {
		d_printf("libxsp_wrapper_read_file(): file open failed: %s", strerror(errno));
		return -1;
	}

	bzero(line, 1024);

	while(fgets(line, 1024, f) != NULL) {
		char *addr_mask;
		char **path;
		int path_count;
		int *ports;
		int port_count;
		int retval;
		int i;

		linelen = strlen(line);

		for(i = 0; i < linelen; i++) {
			if (line[i] == '\n')
				line[i] = '\0';
		}

		retval = libxsp_wrapper_parse_route_line(line, &addr_mask, &path, &path_count, &ports, &port_count);
		if (retval < 0) {
			d_printf("libxsp_wrapper_read_file(): failed to parse line: \"%s\"\n", line);
			continue;
		}

		d_printf("libxsp_wrapper_read_file(): Adding path for: %s\n", addr_mask);

		__libxsp_wrapper_route_add(new_routes, addr_mask, path, path_count, ports, port_count);

		free(addr_mask);

		if (path_count > 0) {
			for(i = 0; i < path_count; i++)
				free(path[i]);
			free(path);
		}

		if (port_count > 0)
			free(ports);

	}

	fclose(f);

	pthread_mutex_lock(&routes_lock);
	old_routes = routes;
	routes = new_routes;
	pthread_mutex_unlock(&routes_lock);

	if(old_routes != NULL) {
		Destroy_Radix(old_routes, libxsp_wrapper_free_path_info);
	}

	return(1);
}

static int libxsp_wrapper_parse_route_line(char *buf, char **ret_addr_mask, char ***ret_path, int *ret_path_count, int **ret_ports, int *ret_port_count) {
	char *addr_mask;
	char **tsv = NULL;
	int tsv_count = 0;
	char **csv = NULL;
	int csv_count = 0;
	int *ports = NULL;
	int port_count = 0;
	char **path;
	int path_count;
	int i;

	tsv = split(buf, "\t", &tsv_count);
	if (!tsv) {
		goto error_exit;
	}

	if (tsv_count < 2 || tsv_count > 3) {
		goto error_exit2;
	}

	addr_mask = tsv[0];
	// next_hop = tsv[1];
	path = split(tsv[1], ",", &path_count);
	if (!path) {
		goto error_exit2;
	}

	if (tsv_count == 3) {
		csv = split(tsv[2], ",", &csv_count);
		if (!csv) {
			goto error_exit2;
		}

		ports = malloc(sizeof(int) * csv_count);
		if (!ports) {
			goto error_exit3;
		}

		for(i = 0; i < csv_count; i++) {
			ports[i] = atoi(csv[i]);
		}

		port_count = csv_count;
	}

	*ret_addr_mask = strdup(addr_mask);

	*ret_path = path;
	*ret_path_count = path_count;

	if (tsv_count == 3) {
		*ret_ports = ports;
		*ret_port_count = port_count;
	} else {
		*ret_ports = NULL;
		*ret_port_count = 0;
	}

	if (csv) {
		for(i = 0; i < csv_count; i++) {
			free(csv[i]);
		}
		free(csv);
	}

	for(i = 0; i < tsv_count; i++) {
		free(tsv[i]);
	}
	free(tsv);

	return 0;

error_exit3:
	for(i = 0; i < csv_count; i++)
		free(csv[i]);
	free(csv);

error_exit2:
	for(i = 0; i < tsv_count; i++)
		free(tsv[i]);
	free(tsv);

error_exit:
	return -1;
}

static void libxsp_wrapper_free_path_info(void *v) {
	struct libxsp_route_path_info *pi = v;
	int i;

	if (pi->port_count > 0)
		free(pi->ports);

	if (pi->path_count > 0) {
		for(i = 0; i < pi->path_count; i++)
			free(pi->path[i]);
		free(pi->path);
	}

	free(pi);
}

const struct libxsp_route_path_info *libxsp_wrapper_route_lookup(const char *hop_id) {
	prefix_t prefix;
	radix_node_t *node;
	struct libxsp_route_path_info *ret_pi;
	struct addrinfo *hop_addr;

	hop_addr = xsp_lookuphop(hop_id);
	if (!hop_addr)
		return NULL;

	prefix.bitlen = 32;
	prefix.family = hop_addr->ai_family;
	// hop_addr->ai_addr
	if (hop_addr->ai_family == AF_INET)
		prefix.add.sin = ((struct sockaddr_in *)hop_addr->ai_addr)->sin_addr;
#ifdef HAVE_IPV6
	else if (hop_addr->ai_family == AF_INET6)
		prefix.add.sin6 = ((struct sockaddr_in6 *)hop_addr->ai_addr)->sin6_addr;
#endif
	else {
		freeaddrinfo(hop_addr);
		return NULL;
	}

	pthread_mutex_lock(&routes_lock);
	{
		if (routes) {

			if ((node = radix_search_best(routes, &prefix)) == NULL) {
				ret_pi = NULL;
			} else {
				ret_pi = node->data;
			}
		} else {
			ret_pi = NULL;
		}

	}
	pthread_mutex_unlock(&routes_lock);

	freeaddrinfo(hop_addr);

	return ret_pi;
}

const struct libxsp_route_path_info *libxsp_wrapper_route_lookup_sa(const struct sockaddr *sa) {
	prefix_t prefix;
	radix_node_t *node;
	struct libxsp_route_path_info *ret_pi;

	prefix.bitlen = 32;
	prefix.family = sa->sa_family;
	// hop_addr->ai_addr
	if (sa->sa_family == AF_INET)
		prefix.add.sin = ((struct sockaddr_in *)sa)->sin_addr;
#ifdef HAVE_IPV6
	else if (hop_addr->sa_family == AF_INET6)
		prefix.add.sin6 = ((struct sockaddr_in6 *)sa)->sin6_addr;
#endif
	else {
		return NULL;
	}

	pthread_mutex_lock(&routes_lock);
	{
		if (routes) {
			if ((node = radix_search_best(routes, &prefix)) == NULL) {
				ret_pi = NULL;
			} else {
				ret_pi = node->data;
			}
		} else {
			ret_pi = NULL;
		}

	}
	pthread_mutex_unlock(&routes_lock);

	return ret_pi;
}

static int xsp_prepare_addrmask(const char *addr_mask, char *output_buf, int buf_size) {
	char *am_dup;
	char *tmp;
	char *tmp_p = NULL;
	char *addr;
	char *ip;
	int netmask;
	struct hostent *he;

	am_dup = strdup(addr_mask);
	if (!am_dup)
		goto error_exit;

	tmp = strtok_r(am_dup, "/", &tmp_p);
	if (!tmp)
		goto error_exit2;

	addr = strdup(tmp);

	tmp = strtok_r(NULL, "/", &tmp_p);
	if (!tmp)
		goto error_exit3;

	netmask = atoi(tmp);

	if (netmask < 0 || netmask > 32)
		goto error_exit3;

	// XXX: this should use getaddrinfo or something
	he = gethostbyname(addr);
	if (!he)
		goto error_exit3;

	tmp = inet_ntoa(*(struct in_addr *)he->h_addr_list[0]);
	if (!tmp)
		goto error_exit4;

	ip = strdup(tmp);
	if (!ip)
		goto error_exit4;

	snprintf(output_buf, buf_size, "%s/%d", ip, netmask);

	free(addr);
	free(am_dup);

	return 0;

error_exit4:
error_exit3:
	free(addr);
error_exit2:
	free(am_dup);
error_exit:
	return -1;
}

static int __libxsp_wrapper_route_add(radix_tree_t *route_tree, const char *addr_mask, const char **path, int path_count, const int *ports, int port_count) {
	radix_node_t *node;
	prefix_t *prefix;
	struct libxsp_route_path_info *path_info;
	char buf[60];
	int i;

	if (xsp_prepare_addrmask(addr_mask, buf, 60) != 0) {
		goto error_exit;
	}

	prefix = ascii2prefix(0, buf);
	if (!prefix) {
		goto error_exit;
	}

	path_info = malloc(sizeof(struct libxsp_route_path_info));
	if (!path_info)
		goto error_exit2;

	if (path_count > 0) {
		path_info->path = malloc(sizeof(char *) * path_count);
		if (!path_info->path) {
			goto error_exit3;
		}

		path_info->path_count = path_count;
	} else {
		path_info->path_count = 0;
		path_info->path = NULL;
	}

	for(i = 0; i < path_count; i++)
		path_info->path[i] = strdup(path[i]);

	if (port_count > 0) {
		path_info->ports = malloc(sizeof(int) * port_count);
		if (!path_info->ports) {
			goto error_exit4;
		}
	} else {
		path_info->port_count = 0;
		path_info->ports = NULL;
	}

	for(i = 0; i < port_count; i++)
		path_info->ports[i] = ports[i];

	path_info->port_count = port_count;

	node = radix_lookup(route_tree, prefix);
	node->data = (void *) path_info;

	Deref_Prefix(prefix);
	return 0;

error_exit4:
	free(path_info->ports);
error_exit3:
	free(path_info);
error_exit2:
	Deref_Prefix(prefix);
error_exit:
	return -1;
}

static int __libxsp_wrapper_route_remove(radix_tree_t *route_tree, const char *addr_mask) {
	radix_node_t *node;
	prefix_t *prefix;
	char buf[60];
	char *hop_id;

	if (xsp_prepare_addrmask(addr_mask, buf, 60) != 0) {
		goto error_exit;
	}

	prefix = ascii2prefix(0, buf);
	if (!prefix) {
		goto error_exit;
	}

	node = radix_search_exact(route_tree, prefix);
	if (!node)
		goto error_exit2;

	hop_id = node->data;

	radix_remove(route_tree, node);

	free(hop_id);

	Deref_Prefix(prefix);

	return 0;

error_exit2:
	Deref_Prefix(prefix);
error_exit:
	return -1;
}

const char *__libxsp_wrapper_route_lookup(radix_tree_t *routes, struct sockaddr *sa) {
	prefix_t prefix;
	radix_node_t *node;

	if (!routes)
		return NULL;

	prefix.bitlen = 32;
	prefix.family = sa->sa_family;
	if (sa->sa_family == AF_INET)
		prefix.add.sin = ((struct sockaddr_in *)sa)->sin_addr;
#ifdef HAVE_IPV6
	else if (hop_addr->ai_family == AF_INET6)
		prefix.add.sin6 = ((struct sockaddr_in6 *)sa)->sin6_addr;
#endif

	node = radix_search_best(routes, &prefix);
	if (!node)
		return NULL;

	return (char *)node->data;
}
