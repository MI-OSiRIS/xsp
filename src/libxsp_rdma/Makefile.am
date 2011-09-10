lib_LIBRARIES = libxsp_rdma.a
lib_LTLIBRARIES = libxsp_rdma.la

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src/libxsp_client -I$(top_srcdir)/compat

libxsp_rdma_a_SOURCES = xsp_rdma.c xsp_rdma.h
libxsp_rdma_la_SOURCES = xsp_rdma.c xsp_rdma.h

libxsp_rdma_a_LIBADD =
libxsp_rdma_la_LIBADD =

libxsp_rdma_la_LDFLAGS = -lm @THREAD_LIBS@ @DL_LIBS@ -export-dynamic @RDMA_LIBS@

libxsp_rdma_a_CFLAGS = @CFLAGS@ -fPIC
libxsp_rdma_la_CFLAGS = @CFLAGS@ -fPIC