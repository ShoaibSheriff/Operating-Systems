#!/bin/sh
# test multiple flags
set -x
echo test multiple flags
/bin/rm -f out.test.$$
./xcpenc -p password123 -d -e in.test.$$ out.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi
