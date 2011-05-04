AUTOMAKE_OPTIONS = foreign

libdirs = src/libxsp libconfig libbson
bindirs = src/xspd

if ENABLE_TERAPATHS
libdirs += libgsoap
bindirs += src/modules/terapaths src/modules/monitoring
endif

if ENABLE_OSCARS
libdirs += libgsoap
bindirs += src/modules/oscars
endif

if ENABLE_CLIENT
libdirs += libradix src/libxsp-client
endif

bindirs += src/modules

SUBDIRS = $(libdirs) $(bindirs)
