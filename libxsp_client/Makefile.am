lib_LIBRARIES = libxsp_client.a
lib_LTLIBRARIES = libxsp_wrapper.la libxsp_simplewrapper.la
include_HEADERS = libxsp_client.h
noinst_HEADERS = libxsp_client_private.h

libxsp_client_a_SOURCES = libxsp_client.c $(top_srcdir)/compat/compat.c $(top_srcdir)/compat/compat.h
libxsp_wrapper_la_SOURCES = libxsp_client.c libxsp_wrapper.c libxsp_wrapper_route.c libxsp_wrapper_route.h $(top_srcdir)/compat/compat.c $(top_srcdir)/compat/compat.h
libxsp_simplewrapper_la_SOURCES = libxsp_client.c libxsp_simplewrapper.c libxsp_wrapper_route.c libxsp_wrapper_route.h $(top_srcdir)/compat/compat.c $(top_srcdir)/compat/compat.h

libxsp_client_a_LIBADD = $(top_builddir)/libxsp/libxsp.o $(top_builddir)/libxsp/libxsp_hop.o $(top_builddir)/libxsp/libxsp_path.o $(top_builddir)/libxsp/libxsp_session.o $(top_builddir)/libxsp/libxsp_protocol_settings.o $(top_builddir)/libxsp/libxsp_proto.o $(top_builddir)/libxsp/libxsp_proto_binary.o $(top_builddir)/libxsp/compat.o
libxsp_wrapper_la_LIBADD = $(top_builddir)/libxsp/libxsp.a $(top_builddir)/libradix/libradix.a
libxsp_simplewrapper_la_LIBADD = $(top_builddir)/libxsp/libxsp.a $(top_builddir)/libradix/libradix.a

libxsp_wrapper_la_LDFLAGS = @THREAD_LIBS@ @DL_LIBS@
libxsp_simplewrapper_la_LDFLAGS = @THREAD_LIBS@ @DL_LIBS@ @NL_LIBS@

INCLUDES = -I@top_srcdir@/include -I@top_srcdir@/libxsp -I@top_srcdir@/libradix -I@top_srcdir@/compat 
AM_CFLAGS = -DUSE_COMPAT_SHA

if HAVE_GLOBUS
libxsp_client_a_SOURCES += tokens.c
libxsp_wrapper_la_SOURCES += tokens.c
libxsp_simplewrapper_la_SOURCES += tokens.c
AM_CFLAGS += "-DHAVE_GLOBUS"
endif

libxsp_client_a_CFLAGS = $(AM_CFLAGS)
