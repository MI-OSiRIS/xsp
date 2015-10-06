noinst_LTLIBRARIES = libgsoap.la
noinst_LIBRARIES = libgsoap.a

noinst_HEADERS      = stdsoap2.h         \
		      xsp_soap_context.h \
		      th-lock.h

libgsoap_la_SOURCES = stdsoap2.c         \
		      th-lock.c          \
		      xsp_soap_context.c
libgsoap_adir = .

libgsoap_a_SOURCES = stdsoap2.c \
		     th-lock.c \
		     xsp_soap_context.c
AM_CFLAGS = -DWITH_NONAMESPACES -DWITH_OPENSSL -DWITH_DOM
AM_CPPFLAGS =
libgsoap_a_CFLAGS = $(AM_CFLAGS)
