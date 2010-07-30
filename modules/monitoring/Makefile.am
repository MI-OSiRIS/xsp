bin_PROGRAMS = client

client_SOURCES = envC.c mntrClientLib.c monitoring.c client.c
client_LDADD = @top_srcdir@/libgsoap/libgsoap.a -lssl -lcrypto

noinst_LIBRARIES = libmntr.a

libmntr_a_SOURCES = envC.c mntrClientLib.c monitoring.c
libmntr_a_LIBADD = @top_srcdir@/libgsoap/libgsoap.a 

AM_CFLAGS =  -DWITH_NONAMESPACES -DWITH_OPENSSL
INCLUDES = -I@top_srcdir@/libgsoap
