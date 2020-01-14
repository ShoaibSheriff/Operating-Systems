#!/bin/sh
# test input file not found
set -x
echo test input file not found
/bin/rm -f out.test.$$
./xcpenc -c "file_absent" out.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi
