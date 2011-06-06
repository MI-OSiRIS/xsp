noinst_PROGRAMS = oscars_client oscars6_client

noinst_LIBRARIES = liboscars.a liboscars6.a
noinst_LTLIBRARIES = liboscars.la liboscars6.la
noinst_HEADERS = oscars.h

oscars_client_SOURCES = oscars_client.c
oscars_client_LDADD = $(top_builddir)/libgsoap/libgsoap.a liboscars.a

oscars6_client_SOURCES = oscars_client.c
oscars6_client_LDADD = $(top_builddir)/libgsoap/libgsoap.a liboscars6.a

liboscars_a_SOURCES = oscarsC.c oscarsClient.c oscars.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c 

liboscars_la_SOURCES = oscarsC.c oscarsClient.c oscars.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c

liboscars6_a_SOURCES = oscars6C.c oscars6Client.c oscars6.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c

liboscars6_la_SOURCES = oscars6C.c oscars6Client.c oscars6.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c

AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -DWITH_DOM -fPIC
AM_LDFLAGS = @SSL_LIBS@

oscars_client_CFLAGS = -DOSCARS5 $(AM_CFLAGS)
oscars6_client_CFLAGS = -DOSCARS6 $(AM_CFLAGS)

liboscars_a_CFLAGS = -DOSCARS5 $(AM_CFLAGS)
liboscars6_a_CFLAGS = -DOSCARS6 $(AM_CFLAGS)
liboscars_la_CFLAGS = -DOSCARS5 $(AM_CFLAGS)
liboscars6_la_CFLAGS = -DOSCARS6 $(AM_CFLAGS)

INCLUDES = -I@top_srcdir@/libgsoap
