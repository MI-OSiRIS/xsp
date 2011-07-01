noinst_PROGRAMS = openflow_client

noinst_LIBRARIES = libopenflow.a
noinst_LTLIBRARIES = libopenflow.la
noinst_HEADERS = openflow.h

#openflow_client_SOURCES = openflow_client.c
#openflow_client_LDADD = $(top_builddir)/libgsoap/libgsoap.a libopenflow.a




libopenflow_a_SOURCES = openflowC.c openflowClient.c openflow.c openflow.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c 

libopenflow_la_SOURCES = openflowC.c openflowClient.c openflow.c openflow.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c





AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -DWITH_DOM -fPIC
AM_LDFLAGS = @SSL_LIBS@

openflow_client_CFLAGS = -Dopenflow $(AM_CFLAGS)


libopenflow_a_CFLAGS = -Dopenflow $(AM_CFLAGS)

libopenflow_la_CFLAGS = -Dopenflow $(AM_CFLAGS)


INCLUDES = -I@top_srcdir@/libgsoap
