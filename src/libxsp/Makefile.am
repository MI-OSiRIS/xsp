noinst_LIBRARIES = libxsp.a

libxsp_a_SOURCES = libxsp.c libxsp_hop.c libxsp_hop.h libxsp_block.c libxsp_block.h libxsp_path.c libxsp_path.h libxsp_session.c libxsp_session.h libxsp_protocol_settings.c libxsp_protocol_settings.h libxsp_proto_binary_v0.c libxsp_proto_binary_v0.h libxsp_proto_binary_v1.c libxsp_proto_binary_v1.h libxsp_proto.c libxsp_proto.h $(top_srcdir)/include/xsp-proto.h $(top_srcdir)/include/xsp.h $(top_srcdir)/compat/compat.c $(top_srcdir)/compat/compat.h

AM_CFLAGS = -fPIC
INCLUDES = -I@top_srcdir@/src/libxsp -I@top_srcdir@/include -I@top_srcdir@/compat -I@top_srcdir@/libconfig
