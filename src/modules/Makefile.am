# this needs to be set as $(libdir)/xspd instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/xspd
modules_LTLIBRARIES =

INCLUDES = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat -I@top_srcdir@/libconfig -I@top_srcdir@/src/xspd 
AM_CFLAGS = @CFLAGS@ -DWITH_OPENSSL -DMODULE_DIR=\"$(moduledir)\" -DCONFIG_FILE=\"$(CONFIG_FILE)\"

#if HAVE_NETFILTER
#modules_LTLIBRARIES += transparent.la
#transparent_la_SOURCES = xspd_frontend_transparent.c
#transparent_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
#endif

modules_LTLIBRARIES += logger_stdout.la
logger_stdout_la_SOURCES = xspd_logger_stdout.c
logger_stdout_la_LDFLAGS = -module -avoid-version -export-dynamic

modules_LTLIBRARIES += logger_file.la
logger_file_la_SOURCES = xspd_logger_file.c
logger_file_la_LDFLAGS = -module -avoid-version -export-dynamic

modules_LTLIBRARIES += logger_syslog.la
logger_syslog_la_SOURCES = xspd_logger_syslog.c
logger_syslog_la_LDFLAGS = -module -avoid-version -export-dynamic

if ENABLE_NLMI
modules_LTLIBRARIES += nlmi.la
nlmi_la_SOURCES = xspd_nlmi.c
nlmi_la_LIBADD = $(top_builddir)/libbson/libbson.a
nlmi_la_CFLAGS = -DMONGO_HAVE_STDINT -I$(top_srcdir)/libbson
nlmi_la_LDFLAGS = -module -avoid-version -export-dynamic
endif

if ENABLE_GLOBUS_XIO
modules_LTLIBRARIES += globus_xio.la
globus_xio_la_SOURCES = xspd_globus_xio.c
globus_xio_la_LIBADD = $(top_builddir)/libbson/libbson.a
globus_xio_la_CFLAGS = -DMONGO_HAVE_STDINT -I$(top_srcdir)/libbson
globus_xio_la_LDFLAGS = -module -avoid-version -export-dynamic
endif

if ENABLE_TERAPATHS
modules_LTLIBRARIES += terapaths.la
terapaths_la_SOURCES = xspd_terapaths_basic.c xspd_terapaths_basic.h
terapaths_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
terapaths_la_LIBADD = terapaths/libterapaths.a monitoring/libmntr.a $(top_builddir)/libgsoap/libgsoap.a
INCLUDES += -I$(srcdir)/terapaths -I$(srcdir)/monitoring -I$(top_srcdir)/libgsoap
endif

if ENABLE_OSCARS
modules_LTLIBRARIES += oscars.la
oscars_la_SOURCES = xspd_oscars_basic.c xspd_oscars_basic.h
oscars_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
oscars_la_LIBADD = oscars/liboscars.a $(top_builddir)/libgsoap/libgsoap.a
oscars_la_CFLAGS = $(AM_CFLAGS) -DOSCARS5 -DWITH_NONAMESPACES -DWITH_DOM
INCLUDES += -I$(srcdir)/oscars -I$(top_srcdir)/libgsoap
endif

if ENABLE_PHOTON
modules_LTLIBRARIES += photon.la
photon_la_SOURCES = xspd_proto_photon.c xspd_proto_photon.h
photon_la_LDFLAGS = -no-undefined -module -avoid-version $(PHOTON_LDFLAGS) -L../../photon/libphoton 
photon_la_LIBADD = $(PHOTON_LIBADD) -lphoton_xsp -ldat2 -lmpi
photon_la_CFLAGS = $(AM_CFLAGS) $(PHOTON_CFLAGS) -I../../photon/libphoton/include -DWITH_XSP
endif

if HAVE_WEB100
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xspd_conn_tcp.c xspd_conn_tcp.h xspd_proto_tcp.c xspd_web100.c xspd_web100.h
tcp_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic @WEB100_LIBS@
tcp_la_CFLAGS = @WEB100_CFLAGS@ -DHAVE_WEB100 $(AM_CFLAGS)
else
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xspd_conn_tcp.c xspd_conn_tcp.h xspd_proto_tcp.c
tcp_la_LDFLAGS = -module -avoid-version -export-dynamic
tcp_la_CFLAGS = $(AM_CFLAGS)
endif

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
endif