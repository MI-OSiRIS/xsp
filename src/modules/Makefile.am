# this needs to be set as $(libdir)/libxsp instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/libxsp
modules_LTLIBRARIES =

INCLUDES = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat -I@top_srcdir@/libconfig -I@top_srcdir@/src/libxsp_common 
AM_CFLAGS = @CFLAGS@ -DWITH_OPENSSL -DMODULE_DIR=\"$(moduledir)\" -DCONFIG_FILE=\"$(CONFIG_FILE)\"

if ENABLE_BLIPP
modules_LTLIBRARIES += blipp.la
blipp_la_SOURCES = xspd_blipp.c
blipp_la_LIBADD = $(top_builddir)/libbson/libbson.a
blipp_la_CFLAGS = -DMONGO_HAVE_STDINT -I$(top_srcdir)/libbson
blipp_la_LDFLAGS = -module -avoid-version -export-dynamic
endif

if ENABLE_PHOTON
modules_LTLIBRARIES += photon.la
photon_la_SOURCES = xspd_proto_photon.c xspd_proto_photon.h
photon_la_LDFLAGS = -no-undefined -module -avoid-version $(PHOTON_LDFLAGS) -L../../photon/libphoton 
photon_la_LIBADD = $(PHOTON_LIBADD) -lphoton_xsp -ldat2 -lmpi
photon_la_CFLAGS = $(AM_CFLAGS) $(PHOTON_CFLAGS) -I../../photon/libphoton/include -DWITH_XSP
endif

if ENABLE_SPEEDOMETER
modules_LTLIBRARIES += speedometer.la
speedometer_la_SOURCES = xspd_speedometer.c
speedometer_la_LDFLAGS = -no-undefined -module -avoid-version
speedometer_la_LIBADD =
speedometer_la_CFLAGS =
endif

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
endif
