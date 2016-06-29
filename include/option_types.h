// =============================================================================
//  DAMSL (xsp)
//
//  Copyright (c) 2010-2016, Trustees of Indiana University,
//  All rights reserved.
//
//  This software may be modified and distributed under the terms of the BSD
//  license.  See the COPYING file for details.
//
//  This software was created at the Indiana University Center for Research in
//  Extreme Scale Technologies (CREST).
// =============================================================================
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

#define STATS_REQ                    0x60
#define STATS_REPLY                  0x61
#define STATS_MIN                    STATS_REQ
#define STATS_MAX                    STATS_REPLY

#endif
