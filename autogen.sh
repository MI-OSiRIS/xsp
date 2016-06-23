# =============================================================================
#  DAMSL (xsp)
#
#  Copyright (c) 2010-2016, Trustees of Indiana University,
#  All rights reserved.
#
#  This software may be modified and distributed under the terms of the BSD
#  license.  See the COPYING file for details.
#
#  This software was created at the Indiana University Center for Research in
#  Extreme Scale Technologies (CREST).
# =============================================================================
#!/bin/sh
if [ ! -d config ]; then mkdir config; fi
URL="https://github.com/periscope-ps/libunis-c.git"
CONTRIB=contrib
dir=libunis-c
CMD_CLONE="git clone"
CMD_PULL="git pull"
if ! type "git" > /dev/null; then
    echo -n "git not found please install git to proceed"
fi
if [ ! -d ${CONTRIB}/$dir ]; then
    echo "Cloning $dir"
    $CMD_CLONE $URL ${CONTRIB}/$dir
    if [ $? -ne 0 ]; then
       echo "Error cloning $dir contrib"
       continue
    fi
else
    echo "Updating $dir - git pull"
    cd ${CONTRIB}/$dir
    $CMD_PULL
    if [ $? -ne 0 ]; then
       echo "Error updating $dir contrib"
       continue
    fi
    cd ../..
fi
set -e
autoreconf --force --install -I config || exit 1
rm -rf autom4te.cache
cd ${CONTRIB}/$dir
./bootstrap.sh
cd ../..
