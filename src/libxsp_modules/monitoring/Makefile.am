bin_PROGRAMS = client

client_SOURCES = envC.c mntrClientLib.c monitoring.c client.c
client_LDADD = $(top_builddir)/libgsoap/libgsoap.a -lssl -lcrypto

noinst_LIBRARIES = libmntr.a

libmntr_a_SOURCES = envC.c mntrClientLib.c monitoring.c
libmntr_a_LIBADD = $(top_builddir)/libgsoap/libgsoap.a 

AM_CFLAGS =  -DWITH_NONAMESPACES -DWITH_OPENSSL -fPIC
AM_CPPFLAGS = -I@top_srcdir@/libgsoap
