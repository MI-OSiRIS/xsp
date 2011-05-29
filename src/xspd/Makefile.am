# this needs to be set as $(libdir)/xspd instead of $(moduledir) so that the RPM
# will install to the correct location.
modulesdir = $(libdir)/xspd
sbin_PROGRAMS = xspd
modules_LTLIBRARIES = 

xspd_SOURCES = xspd.c xspd_frontend.c
xspd_INCLUDES = 
xspd_LDADD = $(top_builddir)/src/libxsp_common/libxsp_common.la $(top_builddir)/src/libxsp/libxsp.a $(top_builddir)/libconfig/libconfig.a

xspd_LDFLAGS = -lm @THREAD_LIBS@ @DL_LIBS@ -export-dynamic @SSL_LIBS@ @NL_LIBS@

if HAVE_LIBRT
xspd_LDFLAGS += -lrt
endif

INCLUDES = -I@top_srcdir@/include -I@top_srcdir@/src/libxsp -I@top_srcdir@/src/libxsp_common -I@top_srcdir@/libradix -I@top_srcdir@/compat -I@top_srcdir@/libconfig 
AM_CFLAGS = @CFLAGS@ -DCONFIG_FILE=\"$(CONFIG_FILE)\"

if HAVE_LIBXML
AM_CFLAGS += @LIBXML_CFLAGS@
xspd_LDFLAGS += @LIBXML_LIBS@
endif
