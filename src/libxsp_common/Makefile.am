lib_LIBRARIES = libxsp_common.a
lib_LTLIBRARIES = libxsp_common.la

libxsp_common_a_SOURCES = xsp_modules.c xsp_session.c xsp_settings.c xsp_settings.h xsp_default_settings.c xsp_default_settings.h xsp_tpool.c xsp_logger.c xsp_logger.h  xsp_protocols.c xsp_conn.c  hashtable.c hashtable.h hashtable_hashfn.c hashtable_util.c hashtable_util.h  xsp_conn.h  xsp_modules.h xsp_protocols.h xsp_session.h xsp_tpool.h $(top_srcdir)/compat/queue.h $(top_srcdir)/compat/compat.c $(top_srcdir)/compat/compat.h xsp_listener.c xsp_listener.h xsp_listener_handler.c xsp_listener_handler.h xsp_common.c xsp_common.h xsp_main_settings.c xsp_main_settings.h xsp_config.c xsp_config.h xsp_path.c xsp_path.h xsp_pathrule.c xsp_pathrule.h xsp_pathrule_handler.c xsp_pathrule_handler.h xsp_measurement.c xsp_measurement.h xsp_user_settings.c xsp_user_settings.h xsp_auth.c xsp_auth.h

libxsp_common_la_SOURCES = xsp_modules.c xsp_session.c xsp_settings.c xsp_settings.h xsp_default_settings.c xsp_default_settings.h xsp_tpool.c xsp_logger.c xsp_logger.h  xsp_protocols.c xsp_conn.c  hashtable.c hashtable.h hashtable_hashfn.c hashtable_util.c hashtable_util.h  xsp_conn.h  xsp_modules.h xsp_protocols.h xsp_session.h xsp_tpool.h $(top_srcdir)/compat/queue.h $(top_srcdir)/compat/compat.c $(top_srcdir)/compat/compat.h xsp_listener.c xsp_listener.h xsp_listener_handler.c xsp_listener_handler.h xsp_common.c xsp_common.h xsp_main_settings.c xsp_main_settings.h xsp_config.c xsp_config.h xsp_path.c xsp_path.h xsp_pathrule.c xsp_pathrule.h xsp_pathrule_handler.c xsp_pathrule_handler.h xsp_measurement.c xsp_measurement.h xsp_user_settings.c xsp_user_settings.h xsp_auth.c xsp_auth.h

libxsp_common_a_LIBADD =
libxsp_common_la_LIBADD =
libxsp_common_la_LDFLAGS = -lm @THREAD_LIBS@ @DL_LIBS@ -export-dynamic @SSL_LIBS@ @NL_LIBS@ @CONFIG_LIBS@

libxsp_common_a_CFLAGS = @CFLAGS@ -DMODULE_DIR=\"$(moduledir)\" -fPIC
libxsp_common_la_CFLAGS = @CFLAGS@ -DMODULE_DIR=\"$(moduledir)\" -fPIC

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/compat

if HAVE_LIBXML
libxsp_common_a_CFLAGS += @LIBXML_CFLAGS@
libxsp_common_la_CFLAGS += @LIBXML_CFLAGS@
libxsp_common_la_LDFLAGS += @LIBXML_LIBS@
endif
