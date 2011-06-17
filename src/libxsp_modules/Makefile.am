# this needs to be set as $(libdir)/libxsp instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/libxsp
modules_LTLIBRARIES =

INCLUDES = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat -I@top_srcdir@/libconfig -I@top_srcdir@/src/libxsp_common
AM_CFLAGS = @CFLAGS@ -DWITH_OPENSSL -DMODULE_DIR=\"$(moduledir)\" -DCONFIG_FILE=\"$(CONFIG_FILE)\"

if HAVE_NETFILTER
modules_LTLIBRARIES += transparent.la
transparent_la_SOURCES = xsp_frontend_transparent.c
transparent_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
endif

modules_LTLIBRARIES += logger_stdout.la
logger_stdout_la_SOURCES = xsp_logger_stdout.c
logger_stdout_la_LDFLAGS = -module -avoid-version -export-dynamic

modules_LTLIBRARIES += logger_file.la
logger_file_la_SOURCES = xsp_logger_file.c
logger_file_la_LDFLAGS = -module -avoid-version -export-dynamic

modules_LTLIBRARIES += logger_syslog.la
logger_syslog_la_SOURCES = xsp_logger_syslog.c
logger_syslog_la_LDFLAGS = -module -avoid-version -export-dynamic

if ENABLE_TERAPATHS
modules_LTLIBRARIES += terapaths.la
terapaths_la_SOURCES = xsp_terapaths_basic.c libxsp_terapaths_basic.h
terapaths_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
terapaths_la_LIBADD = terapaths/libterapaths.a monitoring/libmntr.a $(top_builddir)/libgsoap/libgsoap.a
INCLUDES += -I$(srcdir)/terapaths -I$(srcdir)/monitoring -I$(top_srcdir)/libgsoap
endif

if ENABLE_OSCARS
modules_LTLIBRARIES += oscars5.la oscars6.la
oscars5_la_SOURCES = xsp_oscars_basic.c xsp_oscars_basic.h
oscars5_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
oscars5_la_LIBADD = oscars/liboscars.a $(top_builddir)/libgsoap/libgsoap.a
oscars5_la_CFLAGS = $(AM_CFLAGS) -DOSCARS5 -DWITH_NONAMESPACES -DWITH_DOM
oscars6_la_SOURCES = xsp_oscars_basic.c xsp_oscars_basic.h
oscars6_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic
oscars6_la_LIBADD = oscars/liboscars6.a $(top_builddir)/libgsoap/libgsoap.a
oscars6_la_CFLAGS = $(AM_CFLAGS) -DOSCARS6 -DWITH_NONAMESPACES -DWITH_DOM
INCLUDES += -I$(srcdir)/oscars -I$(top_srcdir)/libgsoap
endif

if HAVE_WEB100
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xsp_conn_tcp.c xsp_conn_tcp.h xsp_proto_tcp.c xsp_web100.c xsp_web100.h
tcp_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic @WEB100_LIBS@
tcp_la_CFLAGS = @WEB100_CFLAGS@ -DHAVE_WEB100 $(AM_CFLAGS)
else
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xsp_conn_tcp.c xsp_conn_tcp.h xsp_proto_tcp.c
tcp_la_LDFLAGS = -module -avoid-version -export-dynamic
tcp_la_CFLAGS = $(AM_CFLAGS)
endif

modules_LTLIBRARIES += auth_anon.la
auth_anon_la_SOURCES = xsp_auth_anon.c xsp_auth_anon.h
auth_anon_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic

modules_LTLIBRARIES += auth_pass.la
auth_pass_la_SOURCES = xsp_auth_pass.c xsp_auth_pass.h
auth_pass_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic

modules_LTLIBRARIES += auth_pass_file.la
auth_pass_file_la_SOURCES = xsp_auth_pass_file.c
auth_pass_file_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic

modules_LTLIBRARIES += auth_trust.la
auth_trust_la_SOURCES = xsp_auth_trusted.c
auth_trust_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic

if HAVE_MYSQL
modules_LTLIBRARIES += auth_pass_mysql.la
auth_pass_mysql_la_SOURCES = xsp_auth_pass_mysql.c
auth_pass_mysql_la_CFLAGS = @MYSQL_CFLAGS@
auth_pass_mysql_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic @MYSQL_LIBS@
endif

if HAVE_SQLITE
modules_LTLIBRARIES += auth_pass_sqlite.la
auth_pass_sqlite_la_SOURCES = xsp_auth_pass_sqlite.c
auth_pass_sqlite_la_CFLAGS = @SQLITE_CFLAGS@
auth_pass_sqlite_la_LDFLAGS = -no-undefined -module -avoid-version -export-dynamic @SQLITE_LIBS@
endif

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
endif
