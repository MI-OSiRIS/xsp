#!/usr/bin/env bash
glibtoolize -c --automake
aclocal
autoheader
autoconf
automake -a
rm -rf autom4te*.cache

pushd libconfig
glibtoolize -c --automake
aclocal
autoheader
autoconf
automake -a
rm -rf autom4te*.cache
popd
