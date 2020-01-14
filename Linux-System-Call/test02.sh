#!/bin/sh
# test short password
set -x
echo test short password
/bin/rm -f out.test.$$
./xcpenc -p pass -e in.test.$$ out.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi
