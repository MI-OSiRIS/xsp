# this needs to be set as $(libdir)/libxsp instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/libxsp
modules_LTLIBRARIES = 

AM_CPPFLAGS = -I@top_srcdir@/compat     \
	      -I@top_srcdir@/include    \
	      -I@top_srcdir@/src/libxsp \
	      -I@top_srcdir@/libradix   \
	      -I@top_srcdir@/libconfig  \
	      -I@top_srcdir@/src/libxsp_common \
              $(LIBXSP_CPPFLAGS)

AM_CFLAGS   = $(LIBHPX_CFLAGS)                 \
	      @CFLAGS@                         \
	      -DWITH_OPENSSL                   \
	      -DMODULE_DIR=\"$(moduledir)\"    \
	      -DCONFIG_FILE=\"$(CONFIG_FILE)\"

AM_LDFLAGS  = -no-undefined -module -avoid-version -export-dynamic

if HAVE_NETFILTER
modules_LTLIBRARIES += transparent.la
transparent_la_SOURCES = xsp_frontend_transparent.c
endif

modules_LTLIBRARIES += logger_stdout.la
logger_stdout_la_SOURCES = xsp_logger_stdout.c

modules_LTLIBRARIES += logger_file.la
logger_file_la_SOURCES = xsp_logger_file.c

modules_LTLIBRARIES += logger_syslog.la
logger_syslog_la_SOURCES = xsp_logger_syslog.c

modules_LTLIBRARIES += peering.la
peering_la_SOURCES = xsp_peering.c xsp_peering.h

if HAVE_LIBUNIS
modules_LTLIBRARIES += unis.la
unis_la_SOURCES = xsp_unis.c xsp_unis.h
if ENABLE_OESS
modules_LTLIBRARIES += auth_cosign.la
auth_cosign_la_SOURCES = xsp_auth_cosign.c
auth_cosign_la_LIBADD  = $(LIBXSP_LIBS) $(LIBXSP_LIBADD)
modules_LTLIBRARIES += oess.la
oess_la_SOURCES = xsp_oess_basic.c
endif
endif

if ENABLE_TERAPATHS
modules_LTLIBRARIES += terapaths.la
terapaths_la_SOURCES = xsp_terapaths_basic.c xsp_terapaths_basic.h
terapaths_la_LIBADD = terapaths/libterapaths.a monitoring/libmntr.a $(top_builddir)/libgsoap/libgsoap.a
AM_CPPFLAGS += -I$(srcdir)/terapaths -I$(srcdir)/monitoring -I$(top_srcdir)/libgsoap
endif

if ENABLE_OSCARS
modules_LTLIBRARIES += oscars5.la oscars6.la
oscars5_la_SOURCES = xsp_oscars_basic.c xsp_oscars_basic.h
oscars5_la_LIBADD = oscars/liboscars.la
oscars5_la_CFLAGS = $(AM_CFLAGS) -DOSCARS5 -DWITH_NONAMESPACES -DWITH_DOM
oscars6_la_SOURCES = xsp_oscars_basic.c xsp_oscars_basic.h
oscars6_la_LIBADD = oscars/liboscars6.la
oscars6_la_CFLAGS = $(AM_CFLAGS) -DOSCARS6 -DWITH_NONAMESPACES -DWITH_DOM
AM_CPPFLAGS += -I$(srcdir)/oscars -I$(top_srcdir)/libgsoap
endif

if ENABLE_OPENFLOW
modules_LTLIBRARIES += openflow.la
openflow_la_SOURCES = xsp_openflow_basic.c xsp_openflow_basic.h
openflow_la_LIBADD = openflow/libofcontrol.a openflow/lib/libopenflow.a
openflow_la_CFLAGS = $(AM_CFLAGS) -DWITH_NONAMESPACES -DWITH_DOM
AM_CPPFLAGS += -I$(srcdir)/openflow/include -I$(srcdir)/openflow
endif

if ENABLE_FLANGE
modules_LTLIBRARIES += flange.la
flange_la_SOURCES = xsp_flange.c
flange_la_LIBADD = $(LIBXSP_LIBS) $(LIBXSP_LIBADD)
endif

if ENABLE_FLOODLIGHT
modules_LTLIBRARIES += floodlight.la
floodlight_la_SOURCES = xsp_floodlight_basic.c xsp_floodlight_basic.h
floodlight_la_LIBADD = $(LIBXSP_LIBS) $(LIBXSP_LIBADD)
endif

if ENABLE_LINUXNET
modules_LTLIBRARIES += linuxnet.la
linuxnet_la_SOURCES = xsp_linuxnet.c xsp_linuxnet.h
linuxnet_la_LIBADD = 
linuxnet_la_CFLAGS = $(AM_CFLAGS)
AM_CPPFLAGS +=
endif

if HAVE_WEB100
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xsp_conn_tcp.c xsp_conn_tcp.h xsp_proto_tcp.c xsp_web100.c xsp_web100.h
tcp_la_LIBADD = @WEB100_LIBS@
tcp_la_CFLAGS = @WEB100_CFLAGS@ -DHAVE_WEB100 $(AM_CFLAGS)
else
modules_LTLIBRARIES += tcp.la
tcp_la_SOURCES = xsp_conn_tcp.c xsp_conn_tcp.h xsp_proto_tcp.c
tcp_la_CFLAGS = $(AM_CFLAGS)
endif

modules_LTLIBRARIES += auth_anon.la
auth_anon_la_SOURCES = xsp_auth_anon.c xsp_auth_anon.h

modules_LTLIBRARIES += auth_pass.la
auth_pass_la_SOURCES = xsp_auth_pass.c xsp_auth_pass.h

if HAVE_OPENSSL
modules_LTLIBRARIES += auth_ssl.la
auth_ssl_la_SOURCES = xsp_auth_ssl.c xsp_auth_ssl.h
endif

modules_LTLIBRARIES += auth_pass_file.la 
auth_pass_file_la_SOURCES = xsp_auth_pass_file.c

modules_LTLIBRARIES += auth_trust.la
auth_trust_la_SOURCES = xsp_auth_trusted.c

if HAVE_MYSQL
modules_LTLIBRARIES += auth_pass_mysql.la
auth_pass_mysql_la_SOURCES = xsp_auth_pass_mysql.c
auth_pass_mysql_la_CFLAGS = @MYSQL_CFLAGS@
auth_pass_mysql_la_LIBADD = @MYSQL_LIBS@
endif

if HAVE_SQLITE
modules_LTLIBRARIES += auth_pass_sqlite.la
auth_pass_sqlite_la_SOURCES = xsp_auth_pass_sqlite.c
auth_pass_sqlite_la_CFLAGS = @SQLITE_CFLAGS@
auth_pass_sqlite_la_LIBADD = @SQLITE_LIBS@
endif

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
endif
