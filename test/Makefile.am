bin_PROGRAMS = xsp_client
sbin_PROGRAMS = 
AM_LDFLAGS = @DL_LIBS@ @THREAD_LIBS@ @SSL_LIBS@
LDADD = $(top_builddir)/libxsp_client/libxsp_client.a

xsp_client_SOURCES = xsp_client.c

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libxsp_client -I$(top_srcdir)/compat

if ENABLE_NLMI
bin_PROGRAMS += nlmi_test

nlmi_test_SOURCES = nlmi_test.c
nlmi_test_CFLAGS = -DMONGO_HAVE_STDINT
LDADD += $(top_builddir)/libbson/libbson.a
INCLUDES += -I$(top_srcdir)/libbson
endif
