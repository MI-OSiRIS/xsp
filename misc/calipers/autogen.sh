#!/bin/sh

set -x
libtoolize -c --automake || glibtoolize -c --automake
aclocal
autoheader
autoconf
automake -a
rm -rf autom4te*.cache

