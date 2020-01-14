#!/bin/sh
# test check contents come back after e->d
set -x
echo check contents come back after e->d
echo First encrypt
/bin/rm -f out.test.$$
./xcpenc -p password123 -e file_in.txt e.txt
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi

echo Now decrypt
./xcpenc -p password123 -d e.txt d.txt
retval=$?
if test $retval != 0 ; then
	echo xcpenc failed with error: $retval
	exit $retval
else
	echo xcpenc program succeeded
fi

# now verify that the two files are the same
if cmp file_in.txt d.txt ; then
	echo "xcpenc: input and decrypted files contents are the same"
	/bin/rm -f e.txt
	/bin/rm -f d.txt
	exit 0
else
	/bin/rm -f e.txt
	/bin/rm -f d.txt
	echo "xcpenc: input and decrypted files contents DIFFER"
	exit 1
fi
