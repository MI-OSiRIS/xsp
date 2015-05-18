noinst_LIBRARIES = libterapaths.a

libterapaths_a_SOURCES = envC.c tpsClientLib.c terapaths.c terapaths.h
libterapaths_a_LIBADD = $(top_builddir)/libgsoap/libgsoap.a 

AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -fPIC
AM_CPPFLAGS = -I@top_srcdir@/libgsoap
