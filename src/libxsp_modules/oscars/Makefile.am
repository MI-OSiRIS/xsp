modulesdir = $(libdir)/libxsp
modules_LTLIBRARIES = 

bin_PROGRAMS = oscars_client oscars6_client

noinst_LTLIBRARIES = liboscars.la liboscars6.la
noinst_HEADERS = oscars.h

oscars_client_SOURCES = oscars_client.c
oscars_client_LDADD = $(top_builddir)/libgsoap/libgsoap.a liboscars.la

oscars6_client_SOURCES = oscars_client.c
oscars6_client_LDADD = $(top_builddir)/libgsoap/libgsoap.a liboscars6.la

liboscars_la_SOURCES = oscarsC.c oscarsClient.c oscars.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c
liboscars6_la_SOURCES = oscars6C.c oscars6Client.c oscars6.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c

liboscars_la_LIBADD = $(top_builddir)/libgsoap/libgsoap.la
liboscars6_la_LIBADD = $(top_builddir)/libgsoap/libgsoap.la

AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -DWITH_DOM -fPIC
AM_LDFLAGS = @SSL_LIBS@

oscars_client_CFLAGS = -DOSCARS5 $(AM_CFLAGS)
oscars6_client_CFLAGS = -DOSCARS6 $(AM_CFLAGS)

liboscars_a_CFLAGS = -DOSCARS5 $(AM_CFLAGS)
liboscars6_a_CFLAGS = -DOSCARS6 $(AM_CFLAGS)
liboscars_la_CFLAGS = -DOSCARS5 $(AM_CFLAGS)
liboscars6_la_CFLAGS = -DOSCARS6 $(AM_CFLAGS)

AM_CPPFLAGS = -I@top_srcdir@/libgsoap
