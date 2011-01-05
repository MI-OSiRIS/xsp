AUTOMAKE_OPTIONS = foreign

libdirs = libxsp libconfig
bindirs = xspd

if ENABLE_TERAPATHS
libdirs += libgsoap
bindirs += modules/terapaths modules/monitoring
endif

if ENABLE_CLIENT
libdirs += libradix libxsp_client
endif

if ENABLE_NLMI
libdirs += modules/libbson
endif

bindirs += modules

SUBDIRS = $(libdirs) $(bindirs)
