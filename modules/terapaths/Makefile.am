noinst_LIBRARIES = libterapaths.a

libterapaths_a_SOURCES = envC.c tpsClientLib.c terapaths.c terapaths.h
libterapaths_a_LIBADD = @top_srcdir@/libgsoap/libgsoap.a 

AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -fPIC
INCLUDES = -I@top_srcdir@/libgsoap
