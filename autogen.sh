#!/usr/bin/env bash
libtoolize -c --automake
aclocal
autoheader
autoconf
automake -a
rm -rf autom4te*.cache
