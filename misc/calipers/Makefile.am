## Process this file with automake to produce Makefile.in
#
# Author: Dan Gunter <dkgunter@lbl.gov>
# Created: 9 Oct 2009
# RCSID: $Id$

# Recurs. dirs

SUBDIRS = . 

# Header files
ACLOCAL_AMFLAGS			 = -I m4
include_HEADERS			 = netlogger_calipers.h bson.h platform_hacks.h

# Library
lib_LTLIBRARIES			 			= libnetlogger_calipers.la
libnetlogger_calipers_la_SOURCES 	= netlogger_calipers.c bson.c numbers.c
#LDADD				 				= libnetlogger_calipers.la

AM_CFLAGS=-DMONGO_HAVE_STDINT -fPIC

clean-local:
	/bin/rm -f *~ *.la *.o *.so
