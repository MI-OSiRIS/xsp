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

#include "libxsp_client.h"

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
	GlobusXIOXSPDebugPrintf(                                 \
        GLOBUS_XIO_XSP_DEBUG_TRACE,                              \
	("[%s] Exiting with error\n", _xio_name))

typedef enum
{
    GLOBUS_XIO_XSP_DEBUG_ERROR = 1,
    GLOBUS_XIO_XSP_DEBUG_WARNING = 2,
    GLOBUS_XIO_XSP_DEBUG_TRACE = 4,
    GLOBUS_XIO_XSP_DEBUG_INFO = 8,
} globus_xio_xsp_debug_levels_t;


static int
globus_l_xio_xsp_activate();

static int
globus_l_xio_xsp_deactivate();

#include "version.h"

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
void
globus_l_xio_xsp_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_finished_open(NULL, op, result);
}

static
globus_result_t
globus_l_xio_xsp_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_xsp_open_cb, NULL);
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
        NULL,
        NULL);

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

    GlobusXIOName(globus_l_xio_xsp_activate);

    GlobusDebugInit(GLOBUS_XIO_XSP, TRACE);
    GlobusXIOXSPDebugEnter();

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	    goto error_xio_system_activate;
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
