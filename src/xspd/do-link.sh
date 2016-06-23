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

for i in ../libxsp/*.[ch]; 
do
ln $i `echo $i | awk -F / '{print $3}'`
done

ln ../include/xsp-proto.h .

ln ../libconfig/config.tab.h .

ln ../compat/compat.c compat.c
ln ../compat/compat.h compat.h
ln ../compat/queue.h queue.h

ln ../libconfig/grammar.c grammar.c
ln ../libconfig/libconfig.c libconfig.c
ln ../libconfig/libconfig.h libconfig.h
ln ../libconfig/private.h private.h
ln ../libconfig/scanner.c scanner.c
ln ../libconfig/scanner.h scanner.h

ln ../include/config.h.junos config.h
