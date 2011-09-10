AUTOMAKE_OPTIONS = foreign

libdirs = libconfig libbson src/libxsp src/libxsp_common
bindirs = src/xspd

if ENABLE_TERAPATHS
libdirs += libgsoap
bindirs += src/libxsp_modules/terapaths src/libxsp_modules/monitoring
endif

if ENABLE_OSCARS
libdirs += libgsoap
bindirs += src/libxsp_modules/oscars
endif

if ENABLE_CLIENT
libdirs += libradix src/libxsp_client
endif

if HAVE_SSH
bindirs += misc/subsys
endif

if HAVE_RDMA
libdirs += src/libxsp_rdma
endif

bindirs += src/libxsp_modules src/modules

SUBDIRS = $(libdirs) $(bindirs)
