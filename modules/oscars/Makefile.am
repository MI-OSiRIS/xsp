noinst_LIBRARIES = liboscars.a
#noinst_LTLIBRARIES = liboscars.la

liboscars_a_SOURCES = envC.c oscarsClientLib.c oscars.c oscars.h dom.c mecevp.c smdevp.c wsaapi.c wsseapi.c 

AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -DWITH_DOM -DOSCARS5 -fPIC
INCLUDES = -I@top_srcdir@/libgsoap
