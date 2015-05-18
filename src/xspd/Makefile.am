sbin_PROGRAMS = xspd

xspd_SOURCES = xspd.c xspd_frontend.c xspd_frontend.h
xspd_INCLUDES = 
xspd_LDADD = $(top_builddir)/src/libxsp_common/libxsp_common.la $(top_builddir)/src/libxsp/libxsp.la

xspd_LDFLAGS = -lm @THREAD_LIBS@ @DL_LIBS@ -export-dynamic @SSL_LIBS@ @NL_LIBS@ @CONFIG_LIBS@

if HAVE_LIBRT
xspd_LDFLAGS += -lrt
endif

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/src/libxsp_common -I@top_srcdir@/libradix -I@top_srcdir@/compat
AM_CFLAGS = @CFLAGS@ -DCONFIG_FILE=\"$(CONFIG_FILE)\"

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
xspd_LDFLAGS += @LIBXML_LIBS@
endif
