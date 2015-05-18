noinst_LTLIBRARIES = libxsp.la

libxsp_la_SOURCES = libxsp.c libxsp_hop.c libxsp_hop.h libxsp_block.c libxsp_block.h libxsp_path.c libxsp_path.h libxsp_net_path.c libxsp_net_path.h libxsp_session.c libxsp_session.h libxsp_protocol_settings.c libxsp_protocol_settings.h libxsp_proto_binary_v0.c libxsp_proto_binary_v0.h libxsp_proto_binary_v1.c libxsp_proto_binary_v1.h libxsp_proto.c libxsp_proto.h $(top_srcdir)/include/xsp-proto.h $(top_srcdir)/include/xsp.h $(top_srcdir)/compat/compat.c $(top_srcdir)/compat/compat.h

AM_CFLAGS = -fPIC
AM_CPPFLAGS = -I@top_srcdir@/src/libxsp -I@top_srcdir@/include -I@top_srcdir@/compat -I@top_srcdir@/libconfig
