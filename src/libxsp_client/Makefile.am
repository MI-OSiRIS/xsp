lib_LTLIBRARIES = libxsp_wrapper.la libxsp_simplewrapper.la libxsp_client.la
include_HEADERS = libxsp_client.h libxsp_client_common.h $(top_srcdir)/include/xsp-proto.h $(top_srcdir)/include/option_types.h
noinst_HEADERS = libxsp_client_private.h

libxsp_client_la_SOURCES = libxsp_client.c
libxsp_wrapper_la_SOURCES = libxsp_client.c libxsp_wrapper.c libxsp_wrapper_route.c libxsp_wrapper_route.h
libxsp_simplewrapper_la_SOURCES = libxsp_client.c libxsp_simplewrapper.c libxsp_wrapper_route.c libxsp_wrapper_route.h

libxsp_client_la_LIBADD = $(top_builddir)/src/libxsp/libxsp.la $(top_builddir)/libradix/libradix.la
libxsp_wrapper_la_LIBADD = $(top_builddir)/src/libxsp/libxsp.la $(top_builddir)/libradix/libradix.la
libxsp_simplewrapper_la_LIBADD = $(top_builddir)/src/libxsp/libxsp.la $(top_builddir)/libradix/libradix.la

libxsp_client_la_LIBADD += @THREAD_LIBS@ @DL_LIBS@ @SSH_LIBS@ @CONFIG_LIBS@
libxsp_wrapper_la_LIBADD += @THREAD_LIBS@ @DL_LIBS@ @SSH_LIBS@ @CONFIG_LIBS@
libxsp_simplewrapper_la_LIBADD += @THREAD_LIBS@ @DL_LIBS@ @NL_LIBS@ @SSH_LIBS@ @CONFIG_LIBS@

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat 
AM_CFLAGS = -DUSE_COMPAT_SHA

if HAVE_SSH
libxsp_client_la_SOURCES += libxsp_ssh.c
libxsp_wrapper_la_SOURCES += libxsp_ssh.c
libxsp_simplewrapper_la_SOURCES += libxsp_ssh.c
endif

if HAVE_GLOBUS
libxsp_client_la_SOURCES += tokens.c
libxsp_wrapper_la_SOURCES += tokens.c
libxsp_simplewrapper_la_SOURCES += tokens.c
AM_CFLAGS += "-DHAVE_GLOBUS"
endif
