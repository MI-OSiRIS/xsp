/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_xsp_driver.h"
#include "version.h"

#include "netlogger_calipers.h"
#include "libxsp_client.h"

#define GLOBUS_XIO_XSP_NEW_XFER          0x30
#define GLOBUS_XIO_XSP_END_XFER          0x31
#define GLOBUS_XIO_XSP_UPDATE_XFER       0x32

#define GLOBUS_XIO_NL_UPDATE_SIZE        65536

GlobusDebugDefine(GLOBUS_XIO_XSP);
GlobusXIODeclareDriver(xsp);

#define GlobusXIOXSPDebugPrintf(level, message)                  \
    GlobusDebugPrintf(GLOBUS_XIO_XSP, level, message)

#define GlobusXIOXSPDebugEnter()                                 \
    GlobusXIOXSPDebugPrintf(                                     \
        GLOBUS_XIO_XSP_DEBUG_TRACE,                              \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOXSPDebugExit()                                  \
    GlobusXIOXSPDebugPrintf(                                     \
        GLOBUS_XIO_XSP_DEBUG_TRACE,                              \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOXSPDebugExitWithError()                         \
    GlobusXIOXSPDebugPrintf(                                     \
        GLOBUS_XIO_XSP_DEBUG_TRACE,                              \
	("[%s] Exiting with error\n", _xio_name))

/* convenience macro that computes E - S, where E and S are type struct timeval, in seconds */
#define SUBTRACT_TV(E,S) (((E).tv_sec - (S).tv_sec) + ((E).tv_usec - (S).tv_usec)/1e6)

typedef enum
{
    GLOBUS_XIO_XSP_DEBUG_ERROR = 1,
    GLOBUS_XIO_XSP_DEBUG_WARNING = 2,
    GLOBUS_XIO_XSP_DEBUG_TRACE = 4,
    GLOBUS_XIO_XSP_DEBUG_INFO = 8,
} globus_xio_xsp_debug_levels_t;


static globus_xio_string_cntl_table_t  xsp_l_string_opts_table[] =
{
    {"stack", GLOBUS_XIO_XSP_CNTL_SET_STACK, globus_xio_string_cntl_string},
    {"xsp_hop", GLOBUS_XIO_XSP_CNTL_SET_HOP, globus_xio_string_cntl_string},
    {"xsp_sec", GLOBUS_XIO_XSP_CNTL_SET_SEC, globus_xio_string_cntl_string},
    {"xsp_blipp", GLOBUS_XIO_XSP_CNTL_SET_BLIPP, globus_xio_string_cntl_string},
    {"xsp_net_path", GLOBUS_XIO_XSP_CNTL_SET_PATH, globus_xio_string_cntl_string},
    {"user", GLOBUS_XIO_XSP_CNTL_SET_USER, globus_xio_string_cntl_string},
    {"task_id", GLOBUS_XIO_XSP_CNTL_SET_TASK, globus_xio_string_cntl_string},
    {"src", GLOBUS_XIO_XSP_CNTL_SET_SRC, globus_xio_string_cntl_string},
    {"dst", GLOBUS_XIO_XSP_CNTL_SET_DST, globus_xio_string_cntl_string},
    {"sport", GLOBUS_XIO_XSP_CNTL_SET_SPORT, globus_xio_string_cntl_int},
    {"dport", GLOBUS_XIO_XSP_CNTL_SET_DPORT, globus_xio_string_cntl_int},
    {"resource", GLOBUS_XIO_XSP_CNTL_SET_RESOURCE, globus_xio_string_cntl_string},
    {"size", GLOBUS_XIO_XSP_CNTL_SET_SIZE, globus_xio_string_cntl_int},
    {"mask", GLOBUS_XIO_XSP_CNTL_SET_MASK, globus_xio_string_cntl_int},
    {"interval", GLOBUS_XIO_XSP_CNTL_SET_INTERVAL, globus_xio_string_cntl_int},
    {NULL, 0, NULL}
};

typedef struct xio_l_xsp_xfer_s
{
    char *                              id;
    char *                              hash_str;
    libxspSess *                        sess;
    libxspSess *                        blipp_sess;
    int                                 xsp_connected; 
    int                                 blipp_connected;
    int                                 xsp_signal_path;
    int                                 streams;
} xio_l_xsp_xfer_t;

typedef struct xio_l_xsp_caliper_s
{
    netlogger_calipers_T                caliper;
    unsigned long                       s_count;
    globus_abstime_t                    ts;
    char *                              event;
} xio_l_xsp_caliper_t;

typedef struct xio_l_xsp_send_args_s
{
    xio_l_xsp_xfer_t *                  xfer;
    void *                              data;
    unsigned int                        length;
    int                                 msg_type;
    int                                 send_mask;
} xio_l_xsp_send_args_t;

typedef struct xio_l_xsp_handle_s
{
    char *                              id;
    xio_l_xsp_xfer_t *                  xfer;

    globus_xio_contact_t *              local_contact;
    globus_xio_contact_t *              remote_contact;
    globus_xio_driver_handle_t          xio_driver_handle;
    
    uint64_t                            filesize;

    int                                 stack;
    char *                              xsp_hop;
    char *                              xsp_sec;
    char *                              xsp_blipp;
    char *                              xsp_net_path;
    char *                              user;
    char *                              task_id;
    char *                              src;
    char *                              dst;
    int                                 sport;
    int                                 dport;
    char *                              resource;
    int                                 size;

    int                                 log_flag;
    int                                 interval;

    xio_l_xsp_caliper_t *               o_caliper;
    xio_l_xsp_caliper_t *               c_caliper;
    xio_l_xsp_caliper_t *               r_caliper;
    xio_l_xsp_caliper_t *               w_caliper;
    xio_l_xsp_caliper_t *               a_caliper;
} xio_l_xsp_handle_t;

static xio_l_xsp_xfer_t                 globus_l_xio_xsp_xfer_default =
{
    GLOBUS_NULL,                        /* id */
    GLOBUS_NULL,                        /* hash_str */
    GLOBUS_NULL,                        /* sess */
    GLOBUS_FALSE,                       /* xsp_connected */
    GLOBUS_FALSE,                       /* xsp_signal_path */
    0                                   /* streams */
};

static xio_l_xsp_handle_t               globus_l_xio_xsp_handle_default =
{
    GLOBUS_NULL,                        /* id */
    GLOBUS_NULL,                        /* xfer */
    GLOBUS_NULL,                        /* local_contact */
    GLOBUS_NULL,                        /* remote_contact */
    GLOBUS_NULL,                        /* xio_driver_handle */
    0,                                  /* filesize */
    GLOBUS_XIO_XSP_NETSTACK,            /* stack */
    GLOBUS_NULL,                        /* xsp_hop */
    GLOBUS_NULL,                        /* xsp_sec */
    GLOBUS_NULL,                        /* xsp_blipp */
    GLOBUS_NULL,                        /* xsp_net_path */
    GLOBUS_NULL,                        /* user */
    GLOBUS_NULL,                        /* task_id */
    GLOBUS_NULL,                        /* src */
    GLOBUS_NULL,                        /* dst */
    0,                                  /* sport */
    0,                                  /* dport */
    GLOBUS_NULL,                        /* resource */
    0,                                  /* size */
    0,                                  /* log_flag, default does not NL log anything */
    0,                                  /* interval */
    GLOBUS_NULL,                        /* o_caliper */
    GLOBUS_NULL,                        /* c_caliper */
    GLOBUS_NULL,                        /* r_caliper */
    GLOBUS_NULL,                        /* w_caliper */
    GLOBUS_NULL                         /* a_caliper */
};

static globus_hashtable_t               xsp_l_xfer_table;
static globus_mutex_t                   xio_l_xsp_mutex;

// Forward declarations and module definition
static
globus_result_t
globus_l_xio_xsp_fileh_query(globus_xio_driver_handle_t driver, int *, int);

static
globus_result_t
globus_l_xio_xsp_setup_contact_info(xio_l_xsp_handle_t * handle);

static
globus_result_t
globus_l_xio_xsp_attr_init(
    void **                             out_attr);

static int
globus_l_xio_xsp_activate();

static int
globus_l_xio_xsp_deactivate();

GlobusXIODefineModule(xsp) =
{
    "globus_xio_xsp",
    globus_l_xio_xsp_activate,
    globus_l_xio_xsp_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
globus_result_t
globus_l_xio_xsp_send_args_init(
    void **                            out_arg,
    void *                             data,
    int                                len,
    int                                msg_type,
    int                                send_mask,
    xio_l_xsp_handle_t *               handle)
{
    xio_l_xsp_send_args_t *            args;
    globus_result_t                    result;

    args = (xio_l_xsp_send_args_t *) globus_malloc(sizeof(xio_l_xsp_send_args_t));
    if (!args)
    {
	result = -1;
	goto error;
    }

    args->data = globus_malloc(len*sizeof(char));
    if (!args->data)
    {
	result = -1;
	goto error_args;
    }

    memcpy(args->data, data, len);
    args->length = len;
    args->msg_type = msg_type;
    args->xfer = handle->xfer;
    args->send_mask = send_mask;
    
    *out_arg = args;
    
    return GLOBUS_SUCCESS;

 error_args:
    globus_free(args);
 error:
    *out_arg = NULL;
    return result;
}

// Define our driver methods
void
globus_l_xio_xsp_send_message(
    void *                              user_arg)
{
    xio_l_xsp_send_args_t *             args;
    globus_result_t                     res;

    args = (xio_l_xsp_send_args_t *) user_arg;
    
    globus_mutex_lock(&xio_l_xsp_mutex);
    {
	if (args->data && (args->length > 0))
        {
		
	    if (args->xfer->xsp_connected &&
		(args->send_mask & GLOBUS_XIO_XSP_SEND_XSPD))
	    {
		res = xsp_send_msg(args->xfer->sess, args->data,
				   args->length, args->msg_type);
	    }
	    
	    if (args->xfer->blipp_connected && 
		(args->send_mask & GLOBUS_XIO_XSP_SEND_BLIPP))
	    {
		res = xsp_send_msg(args->xfer->blipp_sess, args->data,
				   args->length, args->msg_type);
	    }
	    
	    globus_free(args->data);
	    globus_free(args);
	}
    }
    globus_mutex_unlock(&xio_l_xsp_mutex);
}

static
globus_result_t
globus_l_xio_xsp_append_nl_meta(
    bson_buffer *                       bb,
    xio_l_xsp_handle_t *                handle,
    char *                              event,
    char *                              ind)
{
    globus_abstime_t                    now;
    double                              ts;
    int                                 sec, usec;
    char                                portstr[12];

    GlobusTimeAbstimeGetCurrent(now);
    GlobusTimeAbstimeGet(now, sec, usec);
    
    ts = sec + usec/1e6;

    /* start a meta object at the given index */
    bson_append_start_object(bb, ind);
    bson_append_string(bb, "_id", handle->id);
    bson_append_string(bb, "_pid", handle->xfer->id);
    bson_append_string(bb, "event_type", event);

    /* params */
    bson_append_start_object(bb, "params");
    bson_append_double(bb, "dt", handle->interval);
    bson_append_double(bb, "ts", ts);
    bson_append_finish_object(bb);
    
    /* subject */
    bson_append_start_object(bb, "subject");
    if (handle->stack == GLOBUS_XIO_XSP_NETSTACK)
    {
        if (handle->remote_contact->port &&
	    handle->local_contact->port)
	{
	    sprintf(portstr, "%s:%s", handle->local_contact->port,
		    handle->remote_contact->port);
	}
	else if (handle->local_contact->port)
	{
	  sprintf(portstr, "%s:%d", handle->local_contact->port, (int)handle);
	}
	else if  (handle->remote_contact->port)
	{
	  sprintf(portstr, "%d:%s", (int)handle, handle->remote_contact->port);
	}
	else
	{
	    sprintf(portstr, "%d", (int)handle);
	}
	portstr[strlen(portstr)] = '\0';
	bson_append_string(bb, "stream_id", portstr);
    }
    bson_append_finish_object(bb);

    /* finish this meta object */
    bson_append_finish_object(bb);
    
    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_xio_xsp_append_xfer_meta(
    bson_buffer *                       bb,
    xio_l_xsp_handle_t *                handle,
    char *                              ind)
{

    /* start a meta object at the given index */
    bson_append_start_object(bb, ind);
    bson_append_string(bb, "_id", handle->xfer->id);
    bson_append_string(bb, "event_type", "xfer.xsp.xio");

    /* params */
    bson_append_start_object(bb, "params");
    bson_append_finish_object(bb);
    
    /* subject */
    bson_append_start_object(bb, "subject");
    if (handle->task_id != NULL)
    {
	bson_append_string(bb, "task_id", handle->task_id);
    }

    if (handle->stack == GLOBUS_XIO_XSP_NETSTACK)
    {
        bson_append_string(bb, "type", "network");
	if (handle->local_contact->host)
	    bson_append_string(bb, "src", handle->local_contact->host);
	if (handle->remote_contact->host)
	    bson_append_string(bb, "dst", handle->remote_contact->host);
	if (handle->local_contact->port)
	    bson_append_string(bb, "sport", handle->local_contact->port);
	if (handle->remote_contact->port)
	    bson_append_string(bb, "dport", handle->remote_contact->port);
    }
    else if (handle->stack == GLOBUS_XIO_XSP_FSSTACK)
    {
	bson_append_string(bb, "type", "disk");
	bson_append_string(bb, "resource", handle->local_contact->resource);
	bson_append_long(bb, "size", handle->filesize);
    }
    
    /* add all the other driver opts if given*/
    if (handle->user)
	bson_append_string(bb, "u_user", handle->user);
    if (handle->src)
        bson_append_string(bb, "u_src", handle->src);
    if (handle->dst)
        bson_append_string(bb, "u_dst", handle->dst);
    if (handle->sport > 0)
        bson_append_int(bb, "u_sport", handle->sport);
    if (handle->dport > 0)
        bson_append_int(bb, "u_dport", handle->dport);
    if (handle->resource)
        bson_append_string(bb, "u_resource", handle->resource);
    if (handle->size > 0)
        bson_append_int(bb, "u_size", handle->size);

    bson_append_finish_object(bb);

    /* finish this meta object */
    bson_append_finish_object(bb);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_xsp_do_nl_summary(
    xio_l_xsp_handle_t *                handle,
    xio_l_xsp_caliper_t *               c)
{
    globus_result_t                     result;
    char *                              log_event;
    double                              d;
    xio_l_xsp_send_args_t *             args;
    globus_reltime_t                    cb_time;
    bson_buffer                         bb;
    bson *                              bp = NULL;
    int                                 bsz;    

    GlobusTimeReltimeSet(cb_time, 0, 0);

    // print a helpful warning here...
    if (handle->xfer->xsp_connected == GLOBUS_FALSE)
    {
	    fprintf(stderr, "NL_UPDATE: XSP not connected!\n");
    }

    /* get nl caliper data */
    bp = netlogger_calipers_psdata(c->caliper, c->event, handle->id, c->s_count);

    bson_buffer_init(&bb);
    bson_ensure_space(&bb, GLOBUS_XIO_NL_UPDATE_SIZE);
    
    bson_append_string(&bb, "version", "0.1");

    bson_append_start_array(&bb, "data");
    bson_append_bson(&bb, "0", bp);
    bson_append_finish_object(&bb);

    bson_append_start_array(&bb, "meta");
    if (c->s_count == 0)
    {	
      	//globus_l_xio_xsp_append_xfer_meta(&bb, handle, "0");
        globus_l_xio_xsp_append_nl_meta(&bb, handle, c->event, "0");
    }
    bson_append_finish_object(&bb);

    /* get ready to send the bson */
    bp = malloc(sizeof(bson));
    bson_from_buffer(bp, &bb);
    bsz = bson_size(bp);    
    //bson_print(bp);

    result = globus_l_xio_xsp_send_args_init((void**)&args,
					     bp->data,
					     bsz,
					     GLOBUS_XIO_XSP_UPDATE_XFER,
					     GLOBUS_XIO_XSP_SEND_XSPD,
					     handle);
    if (result != GLOBUS_SUCCESS)
    {
	goto error_bp;
    }

    globus_callback_register_oneshot(
	GLOBUS_NULL,
	&cb_time,
	globus_l_xio_xsp_send_message,
	(void*)args);

#if 0
    log_event = netlogger_calipers_log(c->caliper, c->event);
    if (log_event == NULL)
    {
	result = -1;
	goto error;
    }

    printf("Value:\n");
    printf("    sum=%lf mean=%lf\n", c->caliper->sum, c->caliper->mean);
    printf("Log event:\n");
    printf("    %s id=%d\n", log_event, (int)handle);
    printf("Overhead:\n");
    d = c->caliper->dur - c->caliper->dur_sum;
    printf("    begin/end pairs per sec: %lf\n", c->caliper->count / d);
    printf("    usec per begin/end pair: %lf\n", d / c->caliper->count * 1e6);
    printf("    %%overhead: %lf\n", d / c->caliper->dur * 100.);

    globus_free(log_event);
#endif

    netlogger_calipers_clear(c->caliper);
    c->s_count++;

    result = GLOBUS_SUCCESS;

 error_bp:
    if (bp)
    {
	bson_destroy(bp);
	globus_free(bp);
    }
    else
    {
	bson_buffer_destroy(&bb);
    }
    
 error:
    return result;
}

static
globus_result_t
globus_l_xio_xsp_do_xfer_notify(
    xio_l_xsp_handle_t *                handle,
    int                                 notify_type)
{
    globus_result_t                     result;    
    xio_l_xsp_send_args_t *             args;
    globus_reltime_t                    cb_time;
    bson_buffer                         bb;
    bson *                              bp = NULL;
    int                                 bsz;

    GlobusTimeReltimeSet(cb_time, 0, 0);

    /*
    args = (xio_l_xsp_send_args_t *) globus_calloc(1, sizeof(xio_l_xsp_send_args_t));
    args->data = globus_malloc(1024*sizeof(char));
    args->msg_type = notify_type;
    args->xfer = handle->xfer;

    if (handle->stack == GLOBUS_XIO_XSP_NETSTACK)
    {
	sprintf(args->data, "user=%s,task_id=%s,sport=%d,dport=%d,resource=%s,size=%d,src=%s,dst=%s",
		handle->user, handle->task_id, handle->sport, handle->dport, handle->resource,
		handle->size, handle->local_contact->host, handle->remote_contact->host);
    }
    else if (handle->stack == GLOBUS_XIO_XSP_FSSTACK)
    {
	sprintf(args->data, "user=%s,task_id=%s,sport=%d,dport=%d,resource=%s,size=%d,filename=%s,fsize=%u",
                handle->user, handle->task_id, handle->sport, handle->dport, handle->resource,
                handle->size, handle->local_contact->resource, handle->filesize);
    }

    args->length = strlen(args->data);
    */

    // print a helpful warning here...
    if (handle->xfer->xsp_connected == GLOBUS_FALSE)
    {
        printf("NOTIFY: XSP not connected!\n");
    }

    bson_buffer_init(&bb);
    bson_ensure_space(&bb, GLOBUS_XIO_NL_UPDATE_SIZE);

    bson_append_string(&bb, "version", "0.1");

    bson_append_start_array(&bb, "data");
    bson_append_finish_object(&bb);

    bson_append_start_array(&bb, "meta");
    globus_l_xio_xsp_append_xfer_meta(&bb, handle, "0");
    bson_append_finish_object(&bb);

    /* get ready to send the bson */
    bp = malloc(sizeof(bson));
    bson_from_buffer(bp, &bb);
    bsz = bson_size(bp);
    //bson_print(bp);

    result = globus_l_xio_xsp_send_args_init((void**)&args,
					     bp->data,
					     bsz,
					     notify_type,
					     GLOBUS_XIO_XSP_SEND_XSPD | 
					     GLOBUS_XIO_XSP_SEND_BLIPP,
					     handle);
    if (result != GLOBUS_SUCCESS)
    {
	goto error_bp;
    }
    
    globus_callback_register_oneshot(
	GLOBUS_NULL,
	&cb_time,
	globus_l_xio_xsp_send_message,
	(void*)args);


    result = GLOBUS_SUCCESS;

 error_bp:
    if (bp)
    {
	bson_destroy(bp);
	globus_free(bp);
    }
    else
    {
	bson_buffer_destroy(&bb);
    }
    
 error:
    return result;
}

static
globus_result_t
globus_l_xio_xsp_connect_blipp_handle(
    xio_l_xsp_handle_t *                handle)
{
    globus_result_t                     ret;

    GlobusXIOName(xio_l_xsp_connect_blipp_handle);
    GlobusXIOXSPDebugEnter();

    if (handle->xsp_blipp)
    {
	handle->xfer->blipp_sess = xsp_session();
	if (!handle->xfer->blipp_sess)
	{
	    ret = -1;
	    goto error_sess;
	}
	
	ret = xsp_sess_appendchild(handle->xfer->blipp_sess, handle->xsp_blipp, XSP_HOP_NATIVE);
	if (ret != 0)
	{
	    goto error_sess;
	}
	
	ret = xsp_connect(handle->xfer->blipp_sess);
	if (ret != 0)
	{
	    goto error_sess;
	}

	handle->xfer->blipp_connected = GLOBUS_TRUE;
    }
    else
    {
	ret = -1;
	goto error;
    }

    GlobusXIOXSPDebugExit();

    return GLOBUS_SUCCESS;

 error_sess:
    free(handle->xfer->blipp_sess);
 error:
    return ret;
}
static
globus_result_t
globus_l_xio_xsp_connect_handle(
    xio_l_xsp_handle_t *                handle)
{
    globus_result_t                     ret;

    GlobusXIOName(xio_l_xsp_connect_handle);
    GlobusXIOXSPDebugEnter();
    
    if (handle->xsp_hop)
    {
	handle->xfer->sess = xsp_session();
	if (!handle->xfer->sess)
	{
	    ret = -1;
	    goto error;
	}
	
	ret = xsp_sess_appendchild(handle->xfer->sess, handle->xsp_hop, XSP_HOP_NATIVE);
	if (ret != 0)
	{
	    goto error_sess;
	}

	if (handle->xsp_sec && !strcasecmp(handle->xsp_sec, "ssh")) {
	    if ((ret = xsp_sess_set_security(handle->xfer->sess, NULL, XSP_SEC_SSH)) != 0) {
		goto error_sess;
	    }
	}
	
	ret = xsp_connect(handle->xfer->sess);
	if (ret != 0)
	{
	    goto error_sess;
	}

	if (handle->xsp_net_path &&
	    globus_l_xio_xsp_xfer_default.xsp_signal_path)
	{
	    libxspNetPath *path;
	    path = xsp_net_path(handle->xsp_net_path, XSP_NET_PATH_CREATE);
	    if ((ret = xsp_sess_signal_path(handle->xfer->sess, path)) != 0)
	    {
		goto error_sess;
	    }
	    free(path);
	}

	handle->xfer->xsp_connected = GLOBUS_TRUE;
    }
    else
    {
	ret = -1;
	goto error;
    }

    GlobusXIOXSPDebugExit();

    return GLOBUS_SUCCESS;

 error_sess:
    free(handle->xfer->sess);
 error:
    return ret;
}

static
globus_result_t
globus_l_xio_xsp_xfer_init(
    void **                             out_xfer)
{
    xio_l_xsp_xfer_t *                  xfer;
    globus_uuid_t                       uuid;
    int                                 rc;

    xfer = (xio_l_xsp_xfer_t *)
	globus_calloc(1, sizeof(xio_l_xsp_xfer_t));

    xfer->hash_str = NULL;
    xfer->sess = NULL;
    xfer->xsp_connected = GLOBUS_FALSE;
    xfer->blipp_connected = GLOBUS_FALSE;
    xfer->streams = 0;

    rc = globus_uuid_create(&uuid);
    if(rc == 0)
    {
	xfer->id = strdup(uuid.text);
    }
    else
    {
	xfer->id = strdup("default");
    }

    *out_xfer = xfer;
    
    return GLOBUS_SUCCESS;
}   

static
globus_result_t
globus_l_xio_xsp_caliper_init(
    void **                             out_caliper,
    char *                              event)
{
    xio_l_xsp_caliper_t *               cal;
    
    cal = (xio_l_xsp_caliper_t *) globus_malloc(sizeof(xio_l_xsp_caliper_t));
    GlobusTimeAbstimeGetCurrent(cal->ts);
    cal->caliper = netlogger_calipers_new(1);
    cal->s_count = 0;
    cal->event = strdup(event);

    *out_caliper = cal;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_xsp_attr_init(
    void **                             out_attr)
{
    xio_l_xsp_handle_t *                attr;
    globus_uuid_t                       uuid;
    int                                 rc;

    /* intiialize everything to 0 */
    attr = (xio_l_xsp_handle_t *)
        globus_calloc(1, sizeof(xio_l_xsp_handle_t));
    
    attr->filesize = 0;
    attr->xfer = NULL;
    attr->stack = GLOBUS_XIO_XSP_NETSTACK;
    attr->user = NULL;
    attr->task_id = NULL;
    attr->sport = 0;
    attr->dport = 0;
    attr->resource = NULL;
    attr->size = 0;
    attr->log_flag = 0;
    attr->interval = 5;
    attr->id = NULL;
    
    attr->local_contact = globus_calloc(1, sizeof(globus_xio_contact_t));
    attr->remote_contact = globus_calloc(1, sizeof(globus_xio_contact_t));

    rc = globus_uuid_create(&uuid);
    if(rc == 0)
    {
	attr->id = strdup(uuid.text);
    }
    else
    {
	attr->id = strdup("default");
    }
    
    *out_attr = attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_xsp_attr_copy(
    void **                             dst,    
    void *                              src)
{
    xio_l_xsp_handle_t *                dst_attr;
    xio_l_xsp_handle_t *                src_attr;

    src_attr = (xio_l_xsp_handle_t *) src;
    /* intiialize everything to 0 */
    globus_l_xio_xsp_attr_init((void **)&dst_attr);

    if (src_attr->xsp_hop != NULL)
    {
	dst_attr->xsp_hop = strdup(src_attr->xsp_hop);
    }
    else if (globus_l_xio_xsp_handle_default.xsp_hop)
    {
	dst_attr->xsp_hop = strdup(globus_l_xio_xsp_handle_default.xsp_hop);
    }
    else 
    {
	dst_attr->xsp_hop = NULL;
    }

    if (src_attr->xsp_sec != NULL)
    {
	dst_attr->xsp_sec = strdup(src_attr->xsp_sec);
    }
    else if  (globus_l_xio_xsp_handle_default.xsp_sec)
    {
	dst_attr->xsp_sec = strdup(globus_l_xio_xsp_handle_default.xsp_sec);
    }
    else
    {
	dst_attr->xsp_sec = NULL;
    }

    if (src_attr->xsp_blipp != NULL)
    {
	dst_attr->xsp_blipp = strdup(src_attr->xsp_blipp);
    }
    else if (globus_l_xio_xsp_handle_default.xsp_blipp)
    {
	dst_attr->xsp_blipp = strdup(globus_l_xio_xsp_handle_default.xsp_blipp);
    }
    else
    {
	dst_attr->xsp_blipp = NULL;
    }

    if (src_attr->xsp_net_path != NULL)
    {
	dst_attr->xsp_net_path = strdup(src_attr->xsp_net_path);
    }
    else if (globus_l_xio_xsp_handle_default.xsp_net_path)
    {
	dst_attr->xsp_net_path = strdup(globus_l_xio_xsp_handle_default.xsp_net_path);
    }
    else
    {
	dst_attr->xsp_net_path = NULL;
    }
    
    if (src_attr->local_contact)
    {
	globus_xio_contact_copy(dst_attr->local_contact, src_attr->local_contact);
    }

    if (src_attr->remote_contact)
    {
	globus_xio_contact_copy(dst_attr->remote_contact, src_attr->remote_contact);
    }

    if (src_attr->user)
    {
	dst_attr->user = strdup(src_attr->user);
    }

    if (src_attr->task_id)
    {
	dst_attr->task_id = strdup(src_attr->task_id);
    }

    if (src_attr->src)
    {
	dst_attr->src = strdup(src_attr->src);
    }
    
    if (src_attr->dst)
    {
	dst_attr->dst = strdup(src_attr->dst);
    }
    
    if (src_attr->resource)
    {
	dst_attr->resource = strdup(src_attr->resource);
    }

    /* XXX: don't replace the unique handle ID that was just generated! */
    //if (src_attr->id)
    //{
    //  dst_attr->id = strdup(src_attr->id);
    //}

    // only pointer to same xfer struct
    if (src_attr->xfer)
    {
	dst_attr->xfer = src_attr->xfer;
    }

    dst_attr->filesize = src_attr->filesize;
    dst_attr->sport = src_attr->sport;
    dst_attr->dport = src_attr->dport;
    dst_attr->size = src_attr->size;
    dst_attr->stack = src_attr->stack;
    dst_attr->log_flag = src_attr->log_flag;
    dst_attr->interval = src_attr->interval;

    if (src_attr->o_caliper)
	dst_attr->o_caliper = src_attr->o_caliper;
    if (src_attr->c_caliper)
	dst_attr->c_caliper = src_attr->c_caliper;
    if (src_attr->r_caliper)
	dst_attr->r_caliper = src_attr->r_caliper;
    if (src_attr->w_caliper)
	dst_attr->w_caliper = src_attr->w_caliper;
    if (src_attr->a_caliper)
	dst_attr->a_caliper = src_attr->a_caliper;

    *dst = dst_attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_xsp_cntl(
    void  *                             driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char *                              str;
    xio_l_xsp_handle_t *                attr;

    GlobusXIOName(globus_l_xio_xsp_cntl);

    GlobusXIOXSPDebugEnter();

    attr = (xio_l_xsp_handle_t *) driver_attr;

    switch (cmd)
    {
      case GLOBUS_XIO_XSP_CNTL_SET_STACK:
	str= va_arg(ap, char *);
	// the default is NETSTACK
	if (!strcmp(str, "fs"))
	    attr->stack = GLOBUS_XIO_XSP_FSSTACK;
	break;
      case GLOBUS_XIO_XSP_CNTL_SET_HOP:
	  str = va_arg(ap, char *);
	  attr->xsp_hop = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_SEC:
	  str = va_arg(ap, char *);
	  attr->xsp_sec = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_BLIPP:
	  str = va_arg(ap, char *);
	  attr->xsp_blipp = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_PATH:
	  str = va_arg(ap, char *);
	  attr->xsp_net_path = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_USER:
	  str = va_arg(ap, char *);
	  attr->user = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_TASK:
	  str = va_arg(ap, char *);
	  attr->task_id = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_SRC:
	  str = va_arg(ap, char *);
	  attr->src = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_DST:
	  str = va_arg(ap, char *);
	  attr->dst = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_SPORT:
	  attr->sport = va_arg(ap, int);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_DPORT:
	  attr->dport = va_arg(ap, int);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_RESOURCE:
	  str = va_arg(ap, char *);
	  attr->resource = strdup(str);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_SIZE:
	  attr->size = va_arg(ap, int);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_MASK:
	  attr->log_flag = va_arg(ap, int);
	  break;
      case GLOBUS_XIO_XSP_CNTL_SET_INTERVAL:
	  attr->interval = va_arg(ap, int);
	  break;
    }
	
    GlobusXIOXSPDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_xsp_xfer_destroy(
    void *                             xfer_handle)
{
    xio_l_xsp_xfer_t *                 handle;

    if (xfer_handle == NULL)
    {
	return GLOBUS_SUCCESS;
    }

    handle = (xio_l_xsp_xfer_t *) xfer_handle;
    
    if (handle->sess != NULL)
    {
	// already freed in xsp_close
    }
    if (handle->hash_str != NULL)
    {
	globus_free(handle->hash_str);
    }
    if (handle->id != NULL)
    {
	globus_free(handle->id);
    }

    globus_free(handle);
    
    return GLOBUS_SUCCESS;
}   

static
globus_result_t
globus_l_xio_xsp_caliper_destroy(
    void *                              caliper_handle)
{
    xio_l_xsp_caliper_t *               handle;
    
    if (caliper_handle == NULL)
    {
	return GLOBUS_SUCCESS;
    }

    handle = (xio_l_xsp_caliper_t *) caliper_handle;
    
    if (handle->caliper)
    {
	netlogger_calipers_free(handle->caliper);
    }

    if (handle->event)
    {
	globus_free(handle->event);
    }

    globus_free(handle);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_xsp_handle_destroy(
    void *                              driver_handle)
{
    xio_l_xsp_handle_t *                handle;

    if(driver_handle == NULL)
    {
	return GLOBUS_SUCCESS;
    }

    handle = (xio_l_xsp_handle_t *) driver_handle;

    if (handle->xsp_hop != NULL)
    {
	globus_free(handle->xsp_hop);
    }
    if (handle->xsp_sec != NULL)
    {
	globus_free(handle->xsp_sec);
    }
    if (handle->xsp_blipp != NULL)
    {
	globus_free(handle->xsp_blipp);
    }
    if (handle->xsp_net_path != NULL)
    {
	globus_free(handle->xsp_net_path);
    }
    if (handle->local_contact != NULL)
    {
	globus_xio_contact_destroy(handle->local_contact);
    }
    if (handle->remote_contact != NULL)
    {
	globus_xio_contact_destroy(handle->remote_contact);
    }
    if (handle->user != NULL)
    {
	globus_free(handle->user);
    }
    if (handle->task_id != NULL)
    {
	globus_free(handle->task_id);
    }
    if (handle->src != NULL)
    {
	globus_free(handle->src);
    }
    if (handle->dst != NULL)
    {
	globus_free(handle->dst);
    }
    if (handle->resource != NULL)
    {
	globus_free(handle->resource);
    }
    if (handle->id != NULL)
    {
	globus_free(handle->id);
    }

    globus_free(handle);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_xsp_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    xio_l_xsp_handle_t *                handle;
    xio_l_xsp_handle_t *                cpy_handle;
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_xsp_server_init);
    GlobusXIOXSPDebugEnter();

    /* first copy attr if we have it */
    if(driver_attr != NULL)
    {
	cpy_handle = (xio_l_xsp_handle_t *) driver_attr;
    }
    /* else copy the default attr */
    else
    {
	cpy_handle = &globus_l_xio_xsp_handle_default;
    }

    globus_l_xio_xsp_attr_copy((void **)&handle, (void *)cpy_handle);
    res = globus_xio_driver_pass_server_init(op, contact_info, handle);
    if(res != GLOBUS_SUCCESS)
	{
	    goto error_pass;
	}
    GlobusXIOXSPDebugExit();

    return GLOBUS_SUCCESS;
 error_pass:
    GlobusXIOXSPDebugExitWithError();
    return res;
}

static
void
globus_l_xio_xsp_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_xsp_handle_t *                handle;

    GlobusXIOName(globus_l_xio_xsp_accept_cb);
    GlobusXIOXSPDebugEnter();

    handle = (xio_l_xsp_handle_t *) user_arg;
        
    globus_xio_driver_finished_accept(op, user_arg, result);
    GlobusXIOXSPDebugExit();
    return;
}

static
globus_result_t
globus_l_xio_xsp_accept(
    void *                              driver_server,
    globus_xio_operation_t              op)
{
    xio_l_xsp_handle_t *                cpy_handle;
    xio_l_xsp_handle_t *                handle;
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_xsp_accept);
    GlobusXIOXSPDebugEnter();

    cpy_handle = (xio_l_xsp_handle_t *)driver_server;    
    globus_l_xio_xsp_attr_copy((void **)&handle, (void *)cpy_handle);
    
    handle->xio_driver_handle = globus_xio_operation_get_driver_handle(op);
    res = globus_xio_driver_pass_accept(
	   op, globus_l_xio_xsp_accept_cb, handle);
    if(res != GLOBUS_SUCCESS)
	{
	    goto error_pass;
	}

    GlobusXIOXSPDebugExit();
    return GLOBUS_SUCCESS;

 error_pass:
    GlobusXIOXSPDebugExitWithError();
    return res;
}

static
void
globus_l_xio_xsp_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_xsp_xfer_t *                  xfer_handle;
    xio_l_xsp_handle_t *                handle;
    globus_result_t                     res;
    char                                hstring[1024];

    GlobusXIOName(globus_l_xio_xsp_open_cb);
    GlobusXIOXSPDebugEnter();

    handle = (xio_l_xsp_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
	result = GlobusXIOErrorWrapFailedWithMessage(result,
	    "The XSP XIO driver failed to establish a connection%s",
	    " via the underlying transport driver.");
	goto error_destroy_handle;
    }

    // we only get remote contact info if we're on the netstack
    // there has to be a way to ask XIO about what stack this driver is on...
    if (handle->stack == GLOBUS_XIO_XSP_NETSTACK)
    {
	res = globus_l_xio_xsp_setup_contact_info(handle);
	if (res != GLOBUS_SUCCESS)
	{
	    result = GlobusXIOErrorWrapFailed("Could not get contact info for handle.", res);
	    goto error_return;
	}

	//char *tmp;
	//globus_xio_contact_info_to_string(handle->remote_contact, &tmp);
	//printf("CONTACT INFO: %s\n", tmp);
	
	if (handle->xfer == NULL)
	{
	  if (handle->remote_contact->host)
	  {
	      sprintf(hstring, "%s", handle->remote_contact->host);
	      hstring[strlen(hstring)] = '\0';
	  }
	  else
	      hstring[0] = '\0';

	  xfer_handle = (xio_l_xsp_xfer_t *) globus_hashtable_lookup(
		                               &xsp_l_xfer_table, hstring);

	  if (xfer_handle == NULL)
	  {
	      //printf("NEW XFER 2\n");
	      globus_l_xio_xsp_xfer_init((void**)&xfer_handle);
	      xfer_handle->hash_str = strdup(hstring);
	      globus_hashtable_insert(&xsp_l_xfer_table, xfer_handle->hash_str, xfer_handle);
	  }
	  else
	  {
	  }
	  
	  handle->xfer = xfer_handle;
	  
	  globus_l_xio_xsp_caliper_init((void**)&(handle->o_caliper), "nl.open.summary");
	  globus_l_xio_xsp_caliper_init((void**)&(handle->c_caliper), "nl.close.summary");
	  globus_l_xio_xsp_caliper_init((void**)&(handle->r_caliper), "nl.read.summary");
	  globus_l_xio_xsp_caliper_init((void**)&(handle->w_caliper), "nl.write.summary");
	  globus_l_xio_xsp_caliper_init((void**)&(handle->a_caliper), "nl.accept.summary");
	}
    }
    else if (handle->stack == GLOBUS_XIO_XSP_FSSTACK)
    {
	int fd;
	struct stat buf;

	// GLOBUS_XIO_FILE_GET_HANDLE == 0x7
	res = globus_l_xio_xsp_fileh_query(handle->xio_driver_handle,
					   &fd,
					   0x7);
	if (res != GLOBUS_SUCCESS)
        {
	    result = GlobusXIOErrorWrapFailed("Could not get fd from file handle.", res);
	}
					   
	res = fstat(fd, &buf);
	if (res != GLOBUS_SUCCESS)
	{
	    result = GlobusXIOErrorWrapFailed("Could not stat fd.", res);
	}
	else
	{
	  handle->filesize = (uint64_t)buf.st_size;
	}
    }

    if (handle->xfer)
    {
	/* establish session and send transfer notice if not already done */
	globus_mutex_lock(&xio_l_xsp_mutex);
	{
	    // increment active streams for the overall xfer
	    handle->xfer->streams++;

	    if (handle->xfer->xsp_connected == GLOBUS_FALSE)
	    {   
		res = globus_l_xio_xsp_connect_handle(handle);
		if (res != GLOBUS_SUCCESS)
		{
		    res = GlobusXIOErrorWrapFailedWithMessage(res,
			      "The XSP XIO driver failed to establish a connection%s",
							      " to XSPd.");
		    //goto error_return;
		    // this will try again for subsequent streams, if any
		}
	    }

	    if (handle->xfer->blipp_connected == GLOBUS_FALSE)
	    {
		res = globus_l_xio_xsp_connect_blipp_handle(handle);
		if (res != GLOBUS_SUCCESS)
		{
		    res = GlobusXIOErrorWrapFailedWithMessage(res,
			      "The XSP XIO driver failed to establish a connection%s",
							      " to BLiPP");
		    //goto error_return;
		    // this will try again for subsequent streams, if any
		}
	    }

	    // notify on every new stream
	    if (handle->xfer->streams >= 1)
	    {
		res = globus_l_xio_xsp_do_xfer_notify(handle, GLOBUS_XIO_XSP_NEW_XFER);
		if (res != GLOBUS_SUCCESS)
		{
		    res = GlobusXIOErrorWrapFailedWithMessage(res,
			      "The XSP XIO driver failed to send new xfer%s", " message.");
		    //goto error_return;
		}
	    }
	}
	globus_mutex_unlock(&xio_l_xsp_mutex);
    }

 error_return:
    globus_xio_driver_finished_open(user_arg, op, result);
    GlobusXIOXSPDebugExit();

    return;

 error_destroy_handle:
    globus_l_xio_xsp_handle_destroy(handle);
    globus_xio_driver_finished_open(NULL, op, result);
    GlobusXIOXSPDebugExitWithError();
    return;
}

static
globus_result_t
globus_l_xio_xsp_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    xio_l_xsp_xfer_t *                  xfer_handle;
    xio_l_xsp_handle_t *                cpy_handle;
    xio_l_xsp_handle_t *                handle = NULL;
    globus_result_t                     res;
    char                                hstring[1024];
    int                                 hstrlen;

    GlobusXIOName(globus_l_xio_xsp_open);
    GlobusXIOXSPDebugEnter();

    /* first copy attr if we have it */
    if(driver_attr != NULL)
    {
	cpy_handle = (xio_l_xsp_handle_t *) driver_attr;
    }
    else if (driver_link != NULL)
    {
	cpy_handle = (xio_l_xsp_handle_t *) driver_link;
    }
    /* else copy the default attr */
    else
    {
	cpy_handle = &globus_l_xio_xsp_handle_default;
    }
    
    globus_l_xio_xsp_attr_copy((void **)&handle, (void *)cpy_handle);
    
    /* get handle for drivers below us */
    handle->xio_driver_handle = globus_xio_operation_get_driver_handle(op);

    //char *tmp;
    //globus_xio_contact_info_to_string(contact_info, &tmp);
    //printf("CONTACT INFO: %s\n", tmp);

    if (handle->stack == GLOBUS_XIO_XSP_NETSTACK)
    {
        /* save the contact info */
        globus_xio_contact_copy(handle->remote_contact, contact_info);

	if (contact_info->host && contact_info->port)
	{
	    //sprintf(hstring, "%s:%s", contact_info->host, contact_info->port);
	    sprintf(hstring, "%s", contact_info->host);
	}
	else
	    hstring[0] = '\0';
    }
    else if (handle->stack == GLOBUS_XIO_XSP_FSSTACK)
    {
        /* save the contact info */
        globus_xio_contact_copy(handle->local_contact, contact_info);

	if (contact_info->resource)
	    sprintf(hstring, "%s:%d", contact_info->resource, (int)handle);
	else
	    hstring[0] = '\0';
    }
    else
    {
	hstring[0] = '\0';
    }

    hstrlen = strlen(hstring);

    if (hstrlen > 0)
    {
        hstring[hstrlen] = '\0';
	
	//printf("CONTACT_INFO: %s [%d]\n", hstring, hstrlen);

	xfer_handle = (xio_l_xsp_xfer_t *) globus_hashtable_lookup(
		         &xsp_l_xfer_table, hstring);

	if (xfer_handle == NULL)
	{
	    //printf("NEW XFER 1\n");
	    globus_l_xio_xsp_xfer_init((void**)&xfer_handle);
	    xfer_handle->hash_str = strdup(hstring);
	    globus_hashtable_insert(&xsp_l_xfer_table, xfer_handle->hash_str, xfer_handle);
	}
	else
	{
	    // this open is for another stream of the same transfer
	    // we still pass the newly created handle
	}
	
	/* each new handle gets a pointer to the xfer handle */
	handle->xfer = xfer_handle;
	
	/* setup the calipers */
	globus_l_xio_xsp_caliper_init((void**)&(handle->o_caliper), "nl.open.summary");
	globus_l_xio_xsp_caliper_init((void**)&(handle->c_caliper), "nl.close.summary");
	globus_l_xio_xsp_caliper_init((void**)&(handle->r_caliper), "nl.read.summary");
	globus_l_xio_xsp_caliper_init((void**)&(handle->w_caliper), "nl.write.summary");
	globus_l_xio_xsp_caliper_init((void**)&(handle->a_caliper), "nl.accept.summary");

	/* if there's a path to setup, do it before the underlying connection start */
	if ((handle->xfer->xsp_connected == GLOBUS_FALSE) &&
	    globus_l_xio_xsp_xfer_default.xsp_signal_path)
	{
	    res = globus_l_xio_xsp_connect_handle(handle);
	    if (res != GLOBUS_SUCCESS)
	    {
		GlobusXIOErrorWrapFailed("Could not complete XSP PATH.", res);
		return res;
	    }
	}
    }
    else
    {
	handle->xfer = NULL;
    }

    res = globus_xio_driver_pass_open(
	      op, contact_info, globus_l_xio_xsp_open_cb, handle);

    GlobusXIOXSPDebugExit();
    return res;
}

static
void
globus_l_xio_xsp_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_xsp_handle_t *                handle;
    xio_l_xsp_handle_t *                hash_handle;
    globus_result_t                     res;
    globus_abstime_t                    wait_time;
    int                                 done;

    done = GLOBUS_FALSE;

    GlobusXIOName(globus_l_xio_xsp_close_cb);
    GlobusXIOXSPDebugEnter();
    
    handle = (xio_l_xsp_handle_t *)user_arg;
    
    if (handle->xfer)
    {
	globus_mutex_lock(&xio_l_xsp_mutex);
	{
	    handle->xfer->streams--;
	    
	    if ((handle->xfer->streams == 0) &&
		handle->xfer->xsp_connected)
	    {
	      /*
		res = globus_l_xio_xsp_do_xfer_notify(handle, GLOBUS_XIO_XSP_END_XFER);
		if (res != GLOBUS_SUCCESS)
		{
		    res = GlobusXIOErrorWrapFailedWithMessage(res,
			"The XSP XIO driver failed to send end xfer msg%s",
		        " to XSPd.");
		}
		done = GLOBUS_TRUE;
	      */
	    }
	    else
	    {
		// a stream in the active transfer has closed
	    }
	}
	globus_mutex_unlock(&xio_l_xsp_mutex);

	/* free up the calipers */
	globus_l_xio_xsp_caliper_destroy(handle->o_caliper);
	globus_l_xio_xsp_caliper_destroy(handle->c_caliper);
	globus_l_xio_xsp_caliper_destroy(handle->r_caliper);
	globus_l_xio_xsp_caliper_destroy(handle->w_caliper);
	globus_l_xio_xsp_caliper_destroy(handle->a_caliper);
    }

    /* XXX: need a better way to close the active xfer session */
    /* XXX: this waits a second to flush any pending xsp messages before closing */
    if (done)
    {
	int save_errno;
	globus_cond_t xsp_msg_done_cond;
	globus_mutex_t xsp_msg_done_mutex;

	globus_cond_init(&xsp_msg_done_cond, GLOBUS_NULL);
	globus_mutex_init(&xsp_msg_done_mutex, GLOBUS_NULL);

	GlobusTimeAbstimeSet(wait_time, 1, 0);
	
	do {
	    save_errno = globus_cond_timedwait(
		&xsp_msg_done_cond,
		&xsp_msg_done_mutex,
		&wait_time);
	} while (save_errno != ETIMEDOUT);
	
	globus_mutex_lock(&xio_l_xsp_mutex);
	{
	    globus_hashtable_remove(&xsp_l_xfer_table, handle->xfer->hash_str);
	    xsp_close2(handle->xfer->sess);
	    globus_l_xio_xsp_xfer_destroy(handle->xfer);
	}
	globus_mutex_unlock(&xio_l_xsp_mutex);
    }

    globus_xio_driver_finished_close(op, result);

    GlobusXIOXSPDebugExit();
}

static
globus_result_t
globus_l_xio_xsp_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    xio_l_xsp_handle_t *                handle;
    globus_result_t                     res;    

    handle = (xio_l_xsp_handle_t *) driver_specific_handle;

    /* do a final summary before closing */
    /*
    if (handle->xfer && (handle->log_flag & GLOBUS_XIO_XSP_NL_LOG_READ))
    {
	if (handle->r_caliper->caliper->count > 0)
	    globus_l_xio_xsp_do_nl_summary(handle,
					   handle->r_caliper);
    }
    
    if (handle->xfer && (handle->log_flag & GLOBUS_XIO_XSP_NL_LOG_WRITE))
    {
	if (handle->w_caliper->caliper->count > 0)
	    globus_l_xio_xsp_do_nl_summary(handle,
					   handle->w_caliper);
    }
    */

    res = globus_xio_driver_pass_close(
        op, globus_l_xio_xsp_close_cb, handle);
    return res;
}

static
void
globus_l_xio_xsp_read_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_xsp_handle_t *                handle;
    globus_abstime_t                    curr_time;
    globus_reltime_t                    diff;
    int                                 sec, usec;
    
    char *                              log_event;
    double                              d;

    handle = (xio_l_xsp_handle_t *) user_arg;
    if (handle->xfer && (handle->log_flag & GLOBUS_XIO_XSP_NL_LOG_READ))
    {
	netlogger_calipers_end(handle->r_caliper->caliper, nbytes);

	/* we can avoid these Globus macros given the caliper timestamps */
	//GlobusTimeAbstimeGetCurrent(curr_time);
	//GlobusTimeAbstimeDiff(diff, handle->r_caliper->ts, curr_time);
	//GlobusTimeReltimeGet(diff, sec, usec);

	if (SUBTRACT_TV(handle->r_caliper->caliper->end,
			handle->r_caliper->caliper->first)
	    >= handle->interval )
	{
	    globus_l_xio_xsp_do_nl_summary(handle,
					   handle->r_caliper);
	    //GlobusTimeAbstimeGetCurrent(handle->r_caliper->ts);
	}
    }
    
    globus_xio_driver_finished_read(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_xsp_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_size_t                       wait_for;
    globus_result_t                     res;
    xio_l_xsp_handle_t *                handle;

    handle = (xio_l_xsp_handle_t *)driver_specific_handle;
    if(handle->xfer && (handle->log_flag & GLOBUS_XIO_XSP_NL_LOG_READ))
    {
	netlogger_calipers_begin(handle->r_caliper->caliper);
    }

    wait_for = globus_xio_operation_get_wait_for(op);
    //wait_for = GlobusXIOOperationMinimumRead(op);
    res = globus_xio_driver_pass_read(
        op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_xsp_read_cb, handle);

    return res;
}

static
void
globus_l_xio_xsp_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_xsp_handle_t *                handle;
    globus_abstime_t                    curr_time;
    globus_reltime_t                    diff;
    int                                 sec, usec;

    GlobusXIOName(globus_l_xio_xsp_write_cb);
    GlobusXIOXSPDebugEnter();

    handle = (xio_l_xsp_handle_t *) user_arg;
    if (handle->xfer && (handle->log_flag & GLOBUS_XIO_XSP_NL_LOG_WRITE))
    {
	netlogger_calipers_end(handle->w_caliper->caliper, nbytes);
	
	/* we can avoid these Globus macros given the caliper timestamps */
	//GlobusTimeAbstimeGetCurrent(curr_time);
	//GlobusTimeAbstimeDiff(diff, handle->w_caliper->ts, curr_time);
	//GlobusTimeReltimeGet(diff, sec, usec);
	
	if (SUBTRACT_TV(handle->w_caliper->caliper->end,
			handle->w_caliper->caliper->first)
	    >= handle->interval )
	{
	    globus_l_xio_xsp_do_nl_summary(handle,
					   handle->w_caliper);
	    //GlobusTimeAbstimeGetCurrent(handle->w_caliper->ts);
	}
    }
    
    globus_xio_driver_finished_write(op, result, nbytes);
    GlobusXIOXSPDebugExit();
}

static
globus_result_t
globus_l_xio_xsp_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;
    xio_l_xsp_handle_t *                handle;

    handle = (xio_l_xsp_handle_t *)driver_specific_handle;
    if (handle->xfer && (handle->log_flag & GLOBUS_XIO_XSP_NL_LOG_WRITE))
    {
	netlogger_calipers_begin(handle->w_caliper->caliper);
    }

    wait_for = globus_xio_operation_get_wait_for(op);
    //wait_for = GlobusXIOOperationMinimumWrite(op);
    res = globus_xio_driver_pass_write(
	op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_xsp_write_cb, handle);

    return res;
}

static
globus_result_t
globus_l_xio_xsp_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "xsp", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_xsp_open,
        globus_l_xio_xsp_close,
        globus_l_xio_xsp_read,
        globus_l_xio_xsp_write,
	globus_l_xio_xsp_cntl,
        NULL);

    globus_xio_driver_set_server(
	driver,
	globus_l_xio_xsp_server_init,
	globus_l_xio_xsp_accept,
	globus_l_xio_xsp_handle_destroy,
	/* all controls are the same */
	globus_l_xio_xsp_cntl,
	globus_l_xio_xsp_cntl,
	globus_l_xio_xsp_handle_destroy);
    
    globus_xio_driver_set_attr(
        driver,
	globus_l_xio_xsp_attr_init,
	globus_l_xio_xsp_attr_copy,
	/* attr and handle same struct, same controls */
	globus_l_xio_xsp_cntl,
	globus_l_xio_xsp_handle_destroy);
    
    globus_xio_driver_string_cntl_set_table(
	driver,
	xsp_l_string_opts_table);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_xsp_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    xsp,
    globus_l_xio_xsp_init,
    globus_l_xio_xsp_destroy);

static
int
globus_l_xio_xsp_activate(void)
{
    int                                 rc;
    char *                              tmp;

    GlobusXIOName(globus_l_xio_xsp_activate);

    GlobusDebugInit(GLOBUS_XIO_XSP, TRACE);
    GlobusXIOXSPDebugEnter();

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	    goto error_xio_system_activate;
    }

    if ((tmp = globus_module_getenv("XSP_HOP")))
    {
	globus_l_xio_xsp_handle_default.xsp_hop = tmp;
    }
    else
    {
	fprintf(stderr, "XIO-XSP: XSP_HOP not set in environment.\n");
    }

    if ((tmp = globus_module_getenv("XSP_SEC")))
    {
	globus_l_xio_xsp_handle_default.xsp_sec = tmp;
    }
    else
    {
	fprintf(stderr, "XIO-XSP: XSP_SEC not set in environment, using \"none\".\n");
    }

    if ((tmp = globus_module_getenv("XSP_BLIPP")))
    {
	globus_l_xio_xsp_handle_default.xsp_blipp = tmp;
    }

    if ((tmp = globus_module_getenv("XSP_NET_PATH")))
    {
	globus_l_xio_xsp_handle_default.xsp_net_path = tmp;
    }
    
    if ((tmp = globus_module_getenv("XSP_SIGNAL_PATH")))
    {
	globus_l_xio_xsp_xfer_default.xsp_signal_path = GLOBUS_TRUE;
    }

    rc = libxsp_init();
    if (rc != 0) 
    {
	    goto error_xio_system_activate;
    }

    globus_mutex_init(&xio_l_xsp_mutex, NULL);
    globus_hashtable_init(
	&xsp_l_xfer_table,
	128,
	globus_hashtable_string_hash,
	globus_hashtable_string_keyeq);

    GlobusXIORegisterDriver(xsp);

    GlobusXIOXSPDebugExit();
    return GLOBUS_SUCCESS;

 error_xio_system_activate:
    GlobusXIOXSPDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_XSP);
    return rc;
}

static
int
globus_l_xio_xsp_deactivate(void)
{
    GlobusXIOUnRegisterDriver(xsp);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}


static
globus_result_t
globus_l_xio_xsp_fileh_query(
    globus_xio_driver_handle_t          d_handle,
    int *                               fd,
    int                                 cmd)
{
    int                                 ret_fd;
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_xsp_driver_query);
    GlobusXIOXSPDebugEnter();
    
    res = globus_xio_driver_handle_cntl(
	      d_handle,
	      GLOBUS_XIO_QUERY,
	      cmd,
	      &ret_fd);

    if(res != GLOBUS_SUCCESS)
    {
	res = GlobusXIOErrorWrapFailed(
		  "globus_xio_driver_handle_cntl query remote contact",
		  res);
	goto error;
    }

    *fd = ret_fd;

    GlobusXIOXSPDebugExit();
    return GLOBUS_SUCCESS;

 error:
    GlobusXIOXSPDebugExitWithError();
    return res;
}
    

static
globus_result_t
globus_l_xio_xsp_set_ci(
    globus_xio_driver_handle_t          d_handle,
    globus_xio_contact_t **             ci,
    int                                 cmd)
{
    globus_xio_contact_t *              contact_info;
    globus_result_t                     res;
    char *                              contact_string;

    GlobusXIOName(globus_l_xio_xsp_set_ci);
    GlobusXIOXSPDebugEnter();    

    contact_string = NULL;

    res = globus_xio_driver_handle_cntl(
	      d_handle,
	      GLOBUS_XIO_QUERY,
	      cmd,
	      &contact_string);
    if(res != GLOBUS_SUCCESS)
    {
	res = GlobusXIOErrorWrapFailed(
	    "globus_xio_driver_handle_cntl query remote contact",
	    res);
	goto error;
    }

    if (contact_string)
    {
      res = globus_xio_contact_parse(*ci, contact_string);

      if(res != GLOBUS_SUCCESS)
      {
	res = GlobusXIOErrorWrapFailed(
	    "globus_xio_contact_parse", res);
	goto error;
      }
      globus_free(contact_string);
    }
    
    GlobusXIOXSPDebugExit();
    return GLOBUS_SUCCESS;

 error:
    GlobusXIOXSPDebugExitWithError();
    return res;
}	

static
globus_result_t
globus_l_xio_xsp_setup_contact_info(
    xio_l_xsp_handle_t *                handle)
{
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_xsp_setup_contact_info);
    GlobusXIOXSPDebugEnter();

    res = globus_l_xio_xsp_set_ci(handle->xio_driver_handle,
				  &(handle->remote_contact),
				  GLOBUS_XIO_GET_REMOTE_NUMERIC_CONTACT);
    if (res != GLOBUS_SUCCESS)
    {
	goto error;
    }

    res = globus_l_xio_xsp_set_ci(handle->xio_driver_handle,
                                  &(handle->local_contact),
                                  GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT);
    if (res != GLOBUS_SUCCESS)
    {
	goto error;
    }
    
    GlobusXIOXSPDebugExit();
    return GLOBUS_SUCCESS;

 error:
    GlobusXIOXSPDebugExitWithError();
    return res;
}
