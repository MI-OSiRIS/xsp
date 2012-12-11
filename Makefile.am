AUTOMAKE_OPTIONS = foreign

include_HEADERS = include/xsp-proto.h include/config.h

libdirs = libmongo_client src/libxsp src/libxsp_common
bindirs = src/xspd

if ENABLE_TERAPATHS
libdirs += libgsoap
bindirs += src/libxsp_modules/terapaths src/libxsp_modules/monitoring
endif

if ENABLE_OSCARS
libdirs += libgsoap
bindirs += src/libxsp_modules/oscars
endif

if ENABLE_OPENFLOW
bindirs += src/libxsp_modules/openflow
endif

if ENABLE_CLIENT
libdirs += libradix src/libxsp_client
endif

if HAVE_SSH
bindirs += misc/subsys
endif

if HAVE_CURL
libdirs += libcurl
endif

if HAVE_RDMA
libdirs += src/libxsp_rdma
endif

bindirs += src/libxsp_modules src/modules

SUBDIRS = $(libdirs) $(bindirs)
