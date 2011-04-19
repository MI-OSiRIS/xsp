#ifndef OSCARS_H
#define OSCARS_H

#include <stdint.h>

#include "xspd_soap_context.h"
#include "threads.h"
#include "wsseapi.h"

enum boolean_ { false = 0, true = 1 };

enum response_type {
        CREATE_RES = 0,
        CANCEL_RES,
        QUERY_RES,
        MODIFY_RES,
        LIST_RES,
        GET_TOPO,
        REFRESH_PATH,
        TEARDOWN_PATH,
        FORWARD,
        NOTIFY
} rtype;

typedef struct OSCARS_time_t {
	int64_t start_time;
	int64_t end_time;
} OSCARS_time;

typedef struct OSCARS_vlanTag_t {
	char *id;
	enum boolean_ *tagged;
} OSCARS_vlanTag;

typedef struct OSCARS_L2Info_t {
	OSCARS_vlanTag *src_vlan;
	OSCARS_vlanTag *dst_vlan;
	char *src_endpoint;
	char *dst_endpoint;
} OSCARS_L2Info;

typedef struct OSCARS_L3Info_t {
	char *src_host;
	char *dst_host;
	char *protocol;
	int src_port;
	int dst_port;
	char *dscp;
} OSCARS_L3Info;

typedef struct OSCARS_MPLSInfo_t {
	int burst_limit;
	char *lsp_class;
} OSCARS_MPLSInfo;

typedef struct OSCARS_pathInfo_t {
	char *setup_mode;
	char *type;
	void *ctrl_plane_path_content;
	OSCARS_L2Info *l2_info;
	OSCARS_L3Info *l3_info;
	OSCARS_MPLSInfo *mpls_info;
} OSCARS_pathInfo;

typedef struct OSCARS_listRequest_t {
	int size_status;
	char **statuses;
	int size_res_times;
	OSCARS_time **res_times;
	char *description;
	int size_links;
	char **links;
	int size_vlan_tags;
	OSCARS_vlanTag **vlan_tags;
	int res_requested;
	int res_offset;
} OSCARS_listRequest;

typedef struct OSCARS_resRequest_t {
	char *res_id;
	int64_t start_time;
        int64_t end_time;
	int bandwidth;
	char *description;
	OSCARS_pathInfo *path_info;
} OSCARS_resRequest;

void oscars_pretty_print(int type, void *res);

int oscars_createReservation(xspdSoapContext *osc, const OSCARS_resRequest *request, void **response);
int oscars_listReservation(xspdSoapContext *osc, const OSCARS_listRequest *request, void **response);
int oscars_modifyReservation(xspdSoapContext *osc, const OSCARS_resRequest *request, void **response);
int oscars_queryReservation(xspdSoapContext *osc, const char *request, void **response);
int oscars_cancelReservation(xspdSoapContext *osc, const char *request, void **response);
int oscars_getNetworkTopology(xspdSoapContext *osc, const char *request, void **response);

#endif
