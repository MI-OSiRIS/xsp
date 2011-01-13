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


typedef enum globus_xio_xsp_cntl_e
{
	GLOBUS_XIO_XSP_CNTL_SET_HOP = 1,
} globus_xio_xsp_cntl_t;

#endif
