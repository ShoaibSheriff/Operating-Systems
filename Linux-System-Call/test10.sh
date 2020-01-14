#!/bin/sh
# test copy functionality from outside folder
set -x
echo test copy functionality from outside folder
/bin/rm -f out.test.$$
./xcpenc -c /usr/src/hw1-ssheriff/Kbuild out.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi
# now verify that the two files are the same
if cmp "/usr/src/hw1-ssheriff/Kbuild" out.test.$$ ; then
	echo "xcpenc: input and output files contents are the same"
	exit 0
else
	echo "xcpenc: input and output files contents DIFFER"
	exit 1
fi
