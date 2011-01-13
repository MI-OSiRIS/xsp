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

#include "libxsp_client.h"

#define GLOBUS_XIO_NEW_XFER          0x30
#define GLOBUS_XIO_END_XFER          0x31
#define GLOBUS_XIO_UPDATE_XFER       0x32

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

typedef enum
{
    GLOBUS_XIO_XSP_DEBUG_ERROR = 1,
    GLOBUS_XIO_XSP_DEBUG_WARNING = 2,
    GLOBUS_XIO_XSP_DEBUG_TRACE = 4,
    GLOBUS_XIO_XSP_DEBUG_INFO = 8,
} globus_xio_xsp_debug_levels_t;


static globus_xio_string_cntl_table_t  xsp_l_string_opts_table[] =
{
    {"xsp_hop",
     GLOBUS_XIO_XSP_CNTL_SET_HOP, globus_xio_string_cntl_string},
    {NULL, 0, NULL}
};

typedef struct xio_l_xsp_handle_s
{
    libxspSess *                        sess;
    char *                              xsp_hop;
    int                                 streams;
    globus_xio_contact_t *              local_contact;
    globus_xio_contact_t *              remote_contact;
    globus_xio_driver_handle_t          xio_driver_handle;
} xio_l_xsp_handle_t;

static xio_l_xsp_handle_t               globus_l_xio_xsp_handle_default =
{
    GLOBUS_NULL,                        /* sess */
    GLOBUS_NULL,                        /* xsp_hop */
    GLOBUS_NULL,                        /* local_contact */
    GLOBUS_NULL,                        /* remote_contact */
    0,                                  /* streams */
    GLOBUS_NULL                         /* xio_driver_handle */
};

// Forward declarations and module definition
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

// Define our driver methods
static
xio_l_xsp_handle_t *
xio_l_xsp_create_handle(
    xio_l_xsp_handle_t *                handle)
{
    GlobusXIOName(xio_l_xsp_create_handle);
    GlobusXIOXSPDebugEnter();
    
    

    GlobusXIOXSPDebugExit();
    return NULL;
}

static
globus_result_t
globus_l_xio_xsp_attr_init(
    void **                             out_attr)
{
    xio_l_xsp_handle_t *                attr;

    /* intiialize everything to 0 */
    attr = (xio_l_xsp_handle_t *)
        globus_calloc(1, sizeof(xio_l_xsp_handle_t));

    attr->sess = NULL;

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

    if(src_attr->xsp_hop != NULL)
    {
	dst_attr->xsp_hop = strdup(src_attr->xsp_hop);
    }

    if (src_attr->local_contact)
    {
	globus_xio_contact_copy(dst_attr->local_contact, src_attr->local_contact);
    }

    if (src_attr->remote_contact)
    {
	globus_xio_contact_copy(dst_attr->remote_contact, src_attr->remote_contact);
    }

    // only pointer to same session
    dst_attr->sess = src_attr->sess;
    dst_attr->streams = src_attr->streams;

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
      case GLOBUS_XIO_XSP_CNTL_SET_HOP:
	  str= va_arg(ap, char *);
	  attr->xsp_hop = strdup(str);
	  break;
    }
	
    GlobusXIOXSPDebugExit();
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
    if (handle->local_contact != NULL)
    {
	globus_xio_contact_destroy(handle->local_contact);
    }
    if (handle->remote_contact != NULL)
    {
	globus_xio_contact_destroy(handle->remote_contact);
    }
    if (handle->sess != NULL)
    {
	globus_free(handle->sess);
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

    /* first copy attr if we have it */
    if(driver_server != NULL)
    {
	cpy_handle = (xio_l_xsp_handle_t *) driver_server;
    }
    /* else copy the default attr */
    else
    {
	cpy_handle = &globus_l_xio_xsp_handle_default;
    }
    
    globus_l_xio_xsp_attr_copy((void **)&handle, (void *)cpy_handle);
    xio_l_xsp_create_handle(handle);

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
    xio_l_xsp_handle_t *                handle;
    globus_result_t                     res;
    char *                              contact_string;

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

    res = globus_l_xio_xsp_setup_contact_info(handle);
    if (res == GLOBUS_SUCCESS)
    {
	globus_xio_contact_info_to_string(handle->local_contact, &contact_string);
	if (contact_string) {
	    printf("OPEN_CB LOCAL CONTACT INFO: %s\n", contact_string);
	}
	globus_free(contact_string);

	globus_xio_contact_info_to_string(handle->remote_contact, &contact_string);
        if (contact_string) {
            printf("OPEN_CB REMOTE CONTACT INFO: %s\n", contact_string);
        }
	globus_free(contact_string);
    }

    globus_xio_driver_finished_open(NULL, op, result);

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
    xio_l_xsp_handle_t *                cpy_handle;
    xio_l_xsp_handle_t *                handle;
    globus_result_t                     res;

    /* first copy attr if we have it */
    if(driver_attr != NULL)
    {
	cpy_handle = (xio_l_xsp_handle_t *) driver_attr;
    }
    if (driver_link != NULL)
    {
	cpy_handle = (xio_l_xsp_handle_t *) driver_link;
    }
    /* else copy the default attr */
    else
    {
	cpy_handle = &globus_l_xio_xsp_handle_default;
    }
    
    globus_l_xio_xsp_attr_copy((void **)&handle, (void *)cpy_handle);
    xio_l_xsp_create_handle(handle);
    
    handle->xio_driver_handle = globus_xio_operation_get_driver_handle(op);
    
    res = globus_xio_driver_pass_open(
	   op, contact_info, globus_l_xio_xsp_open_cb, handle);
    return res;
}

static
void
globus_l_xio_xsp_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_finished_close(op, result);
}

static
globus_result_t
globus_l_xio_xsp_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    res = globus_xio_driver_pass_close(
        op, globus_l_xio_xsp_close_cb, NULL);
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

    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_read(
        op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_xsp_read_cb, NULL);
    return res;
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

    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_write(
        op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        NULL, NULL);

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
	fprintf(stderr, "Warning: XSP_HOP not set in environment!\n");
    }

    rc = libxsp_init();
    if (rc != 0) 
    {
	    goto error_xio_system_activate;
    }
    
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

    res = globus_xio_driver_handle_cntl(
	      d_handle,
	      GLOBUS_XIO_QUERY,
	      cmd,
	      &contact_string);
    if(res != GLOBUS_SUCCESS)
    {
	res = GlobusXIOErrorWrapFailed(
	    "globus_xio_driver_handle_cntl failed to query remote contact",
	    res);
	goto error;
    }

    contact_info = calloc(1, sizeof(globus_xio_contact_t));
    
    res = globus_xio_contact_parse(contact_info, contact_string);
    globus_free(contact_string);
    if(res != GLOBUS_SUCCESS)
    {
	res = GlobusXIOErrorWrapFailed(
	    "globus_xio_contact_parse", res);
	goto error;
    }
    
    *ci = contact_info;

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
