AUTOMAKE_OPTIONS = foreign

libdirs = libxsp libconfig libbson
bindirs = xspd

if ENABLE_TERAPATHS
libdirs += libgsoap
bindirs += modules/terapaths modules/monitoring
endif

if ENABLE_OSCARS
bindirs += modules/oscars
endif

if ENABLE_CLIENT
libdirs += libradix libxsp_client
endif

bindirs += modules modules/oscars

SUBDIRS = $(libdirs) $(bindirs)
