# this needs to be set as $(libdir)/libxsp instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/libxsp
modules_LTLIBRARIES =

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat -I@top_srcdir@/libconfig -I@top_srcdir@/src/libxsp_common -I@top_srcdir@/src/libxsp_client -I@top_srcdir@/libslabs
AM_CFLAGS = @CFLAGS@ -DWITH_OPENSSL -DMODULE_DIR=\"$(moduledir)\" -DCONFIG_FILE=\"$(CONFIG_FILE)\"

if ENABLE_BLIPP
modules_LTLIBRARIES += blipp.la
blipp_la_SOURCES = xspd_blipp.c
blipp_la_LIBADD = $(top_builddir)/libmongo_client/libmongo_client.a 
blipp_la_CFLAGS = -DMONGO_HAVE_STDINT -I$(top_srcdir)/libmongo_client 
blipp_la_LDFLAGS = -module -avoid-version -export-dynamic
endif

if ENABLE_PHOTON
AM_CFLAGS += $(PHOTON_CFLAGS) -I/home/extern/openmpi-1.6.3/include
modules_LTLIBRARIES += photon.la forwarder.la
photon_la_SOURCES = xspd_proto_photon.c xspd_proto_photon.h
photon_la_LDFLAGS = -no-undefined -module -avoid-version $(PHOTON_LIBS)
photon_la_LIBADD =
forwarder_la_SOURCES = xspd_forwarder.c xspd_forwarder.h
forwarder_la_LIBADD = $(top_builddir)/libmongo_client/libmongo_client.a $(top_builddir)/libslabs/libslabs.a $(top_builddir)/libcurl/libxsp_curl.a @JSON_LIBS@ @CURL_LIBS@
forwarder_la_CFLAGS = $(AM_CFLAGS) -DMONGO_HAVE_STDINT -I$(top_srcdir)/libmongo_client -I$(top_srcdir)/libcurl
forwarder_la_LDFLAGS = -module -avoid-version -export-dynamic
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
