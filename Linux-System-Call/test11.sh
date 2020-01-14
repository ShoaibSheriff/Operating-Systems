#!/bin/sh
# test copy fails for symbolic link
set -x
echo test copy fails for symbolic link
/bin/rm -f out.test.$$
ln -s file_in.txt symlink.txt
./xcpenc -c file_in.txt symlink.txt
retval=$?
/bin/rm -f symlink.txt
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval as expected
	exit $retval
else
	echo xcpenc program succeeded
fi

