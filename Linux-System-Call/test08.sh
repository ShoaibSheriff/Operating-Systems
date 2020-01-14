#!/bin/sh
# test password mismatch
set -x
echo test read permissions - program runs for same password
/bin/rm -f out.test.$$
./xcpenc -p password -e file_in.txt out.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi

./xcpenc -p password1234 -d out.test.$$ "1234.txt"
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi

/bin/rm -f "1234.txt"
