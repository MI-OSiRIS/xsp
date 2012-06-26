bin_PROGRAMS = xsp_client xsp_linuxnet xsp_pathtest
sbin_PROGRAMS = 
AM_LDFLAGS = @DL_LIBS@ @THREAD_LIBS@ @SSL_LIBS@
LDADD = $(top_builddir)/src/libxsp_client/libxsp_client.a

xsp_client_SOURCES = xsp_client.c
xsp_linuxnet_SOURCES = xsp_linuxnet.c
xsp_pathtest_SOURCES = xsp_pathtest.c

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src/libxsp_client -I$(top_srcdir)/compat

if ENABLE_NLMI
bin_PROGRAMS += nlmi_test

nlmi_test_SOURCES = nlmi_test.c
nlmi_test_CFLAGS = -DMONGO_HAVE_STDINT
LDADD += $(top_builddir)/libbson/libbson.a
INCLUDES += -I$(top_srcdir)/libbson
endif


if HAVE_SSH
LDADD += @SSH_LIBS@
endif
