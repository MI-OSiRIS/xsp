# this needs to be set as $(libdir)/xspd instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/xspd
modules_LTLIBRARIES =

INCLUDES = -I@top_srcdir@/include -I@top_srcdir@/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat -I@top_srcdir@/libconfig -I@top_srcdir@/xspd 
AM_CFLAGS = @CFLAGS@ -DWITH_OPENSSL -DMODULE_DIR=\"$(moduledir)\" -DCONFIG_FILE=\"$(CONFIG_FILE)\"

#if HAVE_NETFILTER
#modules_LTLIBRARIES += transparent.la
#transparent_la_SOURCES = xspd_frontend_transparent.c
#transparent_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
#endif

modules_LTLIBRARIES += logger_stdout.la
logger_stdout_la_SOURCES = xspd_logger_stdout.c
logger_stdout_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic

modules_LTLIBRARIES += logger_file.la
logger_file_la_SOURCES = xspd_logger_file.c
logger_file_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic

modules_LTLIBRARIES += logger_syslog.la
logger_syslog_la_SOURCES = xspd_logger_syslog.c
logger_syslog_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic

if ENABLE_TERAPATHS
modules_LTLIBRARIES += terapaths.la
terapaths_la_SOURCES = xspd_terapaths_basic.c xspd_terapaths_basic.h
terapaths_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
terapaths_la_LIBADD = terapaths/libterapaths.a monitoring/libmntr.a ../libgsoap/libgsoap.a
INCLUDES += -I./terapaths -I./monitoring -I../libgsoap
endif

if ENABLE_OSCARS
modules_LTLIBRARIES += oscars.la
oscars_la_SOURCES = xspd_oscars_basic.c oscars.c oscars.h
oscars_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
endif

if HAVE_WEB100
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xspd_conn_tcp.c xspd_conn_tcp.h xspd_proto_tcp.c xspd_web100.c xspd_web100.h
tcp_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic @WEB100_LIBS@
tcp_la_CFLAGS = @WEB100_CFLAGS@ -DHAVE_WEB100 $(AM_CFLAGS)
else
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xspd_conn_tcp.c xspd_conn_tcp.h xspd_proto_tcp.c
tcp_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
tcp_la_CFLAGS = $(AM_CFLAGS)
endif

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
endif
