#ifndef OPTION_TYPES_H
#define OPTION_TYPES_H

#define PHOTON_CI                    0x00
#define PHOTON_RI                    0x01
#define PHOTON_SI                    0x02
#define PHOTON_FI                    0x03
#define PHOTON_IO                    0x06
#define PHOTON_MIN                   PHOTON_CI
#define PHOTON_MAX                   PHOTON_IO

#define SLAB_INFO	             0x10
#define SLAB_MIN                     SLAB_INFO
#define SLAB_MAX                     SLAB_INFO

#define NLMI_BSON	             0x20
#define NLMI_MIN	             NLMI_BSON
#define NLMI_MAX	             NLMI_BSON

#define GLOBUS_XIO_NEW_XFER          0x30
#define GLOBUS_XIO_END_XFER          0x31
#define GLOBUS_XIO_UPDATE_XFER       0x32
#define GLOBUS_XIO_MIN               GLOBUS_XIO_NEW_XFER
#define GLOBUS_XIO_MAX               GLOBUS_XIO_UPDATE_XFER

#endif
