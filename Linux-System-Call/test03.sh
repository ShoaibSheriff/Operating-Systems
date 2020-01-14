#!/bin/sh
# test incomplete paramters
set -x
echo test incomplete params
/bin/rm -f out.test.$$
./xcpenc -c in.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi
