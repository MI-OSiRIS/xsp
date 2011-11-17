#if !defined GLOBUS_XIO_XSP_DRIVER_H
#define GLOBUS_XIO_XSP_DRIVER_H 1

typedef struct globus_xio_xsp_new_msg_s
{
    char *src;
    char *dst;
    int sport;
    int dport;
    
    char *user;
    char *resource;
} globus_xio_xsp_new_msg_t;

typedef struct globus_xio_xsp_end_msg_s
{
    // some kind of end info
    // netlogger

} globus_xio_xsp_end_msg_t;

typedef struct globus_xio_xsp_update_msg_s 
{
    int streams;
    
    // netlogger

} globus_xio_xsp_update_msg_t;

#define GLOBUS_XIO_XSP_NETSTACK     0
#define GLOBUS_XIO_XSP_FSSTACK      1

typedef enum globus_xio_xsp_send_mask_e
{
    GLOBUS_XIO_XSP_SEND_XSPD = 0x1,
    GLOBUS_XIO_XSP_SEND_BLIPP = 0x2
} globus_xio_xsp_send_mask;

typedef enum globus_xio_netlogger_log_event_e
{
    GLOBUS_XIO_XSP_NL_LOG_OPEN = 0x1,
    GLOBUS_XIO_XSP_NL_LOG_CLOSE = 0x2,
    GLOBUS_XIO_XSP_NL_LOG_READ = 0x4,
    GLOBUS_XIO_XSP_NL_LOG_WRITE = 0x8,
    GLOBUS_XIO_XSP_NL_LOG_ACCEPT = 0x10
} globus_xio_netlogger_log_event_t;

typedef enum globus_xio_xsp_cntl_e
{
    GLOBUS_XIO_XSP_CNTL_SET_STACK = 1,
    GLOBUS_XIO_XSP_CNTL_SET_HOP,
    GLOBUS_XIO_XSP_CNTL_SET_SEC,
    GLOBUS_XIO_XSP_CNTL_SET_BLIPP,
    GLOBUS_XIO_XSP_CNTL_SET_PATH,
    GLOBUS_XIO_XSP_CNTL_SET_USER,
    GLOBUS_XIO_XSP_CNTL_SET_TASK,
    GLOBUS_XIO_XSP_CNTL_SET_SRC,
    GLOBUS_XIO_XSP_CNTL_SET_DST,
    GLOBUS_XIO_XSP_CNTL_SET_SPORT,
    GLOBUS_XIO_XSP_CNTL_SET_DPORT,
    GLOBUS_XIO_XSP_CNTL_SET_RESOURCE,
    GLOBUS_XIO_XSP_CNTL_SET_SIZE,
    GLOBUS_XIO_XSP_CNTL_SET_MASK,
    GLOBUS_XIO_XSP_CNTL_SET_INTERVAL,
    GLOBUS_XIO_XSP_CNTL_SET_DPID,
    GLOBUS_XIO_XSP_CNTL_SET_THRESH,
    GLOBUS_XIO_XSP_CNTL_SET_TRESH_INTERVAL
} globus_xio_xsp_cntl_t;

#endif
