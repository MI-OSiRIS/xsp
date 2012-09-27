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

#define BLIPP_BSON_META	             0x20
#define BLIPP_BSON_DATA              0x21
#define BLIPP_MIN	             BLIPP_BSON_META
#define BLIPP_MAX	             BLIPP_BSON_DATA

#define SPEEDOMETER_UPDATE           0x40
#define SPEEDOMETER_MIN              SPEEDOMETER_UPDATE
#define SPEEDOMETER_MAX              SPEEDOMETER_UPDATE

#define PEERING_HELLO                0x50
#define PEERING_BYE                  0x51
#define PEERING_MIN                  PEERING_HELLO
#define PEERING_MAX                  PEERING_BYE

#endif
