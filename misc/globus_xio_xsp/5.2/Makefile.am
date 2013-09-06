include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata 

flavorinclude_HEADERS = \
    globus_xio_xsp_driver.h

NL_PATH=/usr/local

INCLUDES = $(GPT_INCLUDES) -I$(XSP_PATH)/include -I$(NL_PATH)/include
LDFLAGS = -L$(XSP_PATH)/lib
CFLAGS = -DMONGO_HAVE_STDINT

lib_LTLIBRARIES = libglobus_xio_xsp_driver.la

libglobus_xio_xsp_driver_la_LIBADD = \
	@GPT_LIB_LINKS@ $(XSP_PATH)/lib/libxsp_client.so  $(NL_PATH)/lib/libnetlogger_calipers.a
libglobus_xio_xsp_driver_la_SOURCES = \
	globus_xio_xsp_driver.c
libglobus_xio_xsp_driver_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib -lxsp_client -lpthread

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
