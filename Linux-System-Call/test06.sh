#!/bin/sh
# test read permissions - run from non root user
set -x
echo test read permissions - run from non root user
/bin/rm -f out.test.$$
./xcpenc -c no_permissions.txt out.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi