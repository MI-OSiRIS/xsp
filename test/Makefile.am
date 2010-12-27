bin_PROGRAMS = xsp_client
sbin_PROGRAMS = 
AM_LDFLAGS = @DL_LIBS@ @THREAD_LIBS@ @SSL_LIBS@
LDADD = ../libxsp/libxsp.a

xsp_client_SOURCES = xsp_client.c
xsp_client_LDADD = ..//libxsp_client/libxsp_client.a ../libxsp/libxsp.a

INCLUDES = -I../include -I../libxsp_client -I../libxsp -I../compat
