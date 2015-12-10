bin_PROGRAMS = xsp_client xsp_linuxnet xsp_pathtest
sbin_PROGRAMS = 
AM_LDFLAGS = 
LDADD = $(top_builddir)/compat/libcompat.la                \
	$(top_builddir)/src/libxsp_client/libxsp_client.la \
	@DL_LIBS@ @THREAD_LIBS@ @SSL_LIBS@

xsp_client_SOURCES = xsp_client.c
xsp_linuxnet_SOURCES = xsp_linuxnet.c
xsp_pathtest_SOURCES = xsp_pathtest.c

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/libxsp_client -I$(top_srcdir)/compat

if ENABLE_BLIPP
bin_PROGRAMS += blipp_test
blipp_test_SOURCES = blipp_test.c
blipp_test_CFLAGS = -DMONGO_HAVE_STDINT
LDADD += $(top_builddir)/libmongo_client/libmongo_client.a
AM_CPPFLAGS += -I$(top_srcdir)/libmongo_client
endif


if HAVE_SSH
LDADD += @SSH_LIBS@
endif
