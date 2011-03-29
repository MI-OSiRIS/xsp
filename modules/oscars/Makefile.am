noinst_LIBRARIES = liboscars.a
#noinst_LTLIBRARIES = liboscars.la

liboscars_a_SOURCES = oscarsClientLib.c oscars.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c 
liboscars_a_LIBADD = $(top_builddir)/libgsoap/libgsoap.a 

AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -DWITH_DOM -fPIC
INCLUDES = -I@top_srcdir@/libgsoap
