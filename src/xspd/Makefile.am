# this needs to be set as $(libdir)/xspd instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/src/xspd
sbin_PROGRAMS = xspd
modules_LTLIBRARIES = 

xspd_SOURCES = xspd.c xspd_modules.c xspd_session.c  xspd_settings.c xspd_settings.h xspd_default_settings.c xspd_default_settings.h xspd_tpool.c xspd_logger.c xspd_logger.h  xspd_protocols.c xspd_conn.c  hashtable.c hashtable.h  xspd_conn.h  xspd_modules.h xspd_protocols.h xspd_session.h xspd_tpool.h $(top_srcdir)/compat/queue.h $(top_srcdir)/compat/compat.c ../compat/compat.h xspd_listener.c xspd_listener.h xspd_listener_handler.c xspd_listener_handler.h xspd_common.c xspd_common.h xspd_frontend_default.c xspd_frontend_default.h xspd_main_settings.c xspd_main_settings.h xspd_config.c xspd_config.h xspd_path.c xspd_path.h xspd_path_handler.c xspd_path_handler.h xspd_channel.c xspd_channel.h
xspd_INCLUDES = 
xspd_LDADD = $(top_builddir)/src/libxsp/libxsp.a $(top_builddir)/libconfig/libconfig.a 

xspd_LDFLAGS = -lm @THREAD_LIBS@ @DL_LIBS@ -export-dynamic @SSL_LIBS@ @NL_LIBS@

if HAVE_LIBRT
xspd_LDFLAGS += -lrt
endif

INCLUDES = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat -I@top_srcdir@/libconfig 
AM_CFLAGS = @CFLAGS@ -DMODULE_DIR=\"$(moduledir)\" -DCONFIG_FILE=\"$(CONFIG_FILE)\"

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
xspd_LDFLAGS += @LIBXML_LIBS@
endif
