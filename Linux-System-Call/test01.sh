#!/bin/sh
# test basic copy functionality
set -x
echo Test basic copy functionality
/bin/rm -f out.test.$$
echo Test for basic copy > in.test.$$
./xcpenc -c in.test.$$ out.test.$$
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi
# now verify that the two files are the same
if cmp in.test.$$ out.test.$$ ; then
	echo "xcpenc: input and output files contents are the same"
	exit 0
else
	echo "xcpenc: input and output files contents DIFFER"
	exit 1
fi
