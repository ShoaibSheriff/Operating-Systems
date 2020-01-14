#!/bin/sh
echo "<-- restore files - restore oldest -->"
echo "<-- successful with output -->"
# set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

max_bkps=5
file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o "maxver=$max_bkps" /test/bkpfs /mnt/bkpfs

echo 123456789 > "/mnt/bkpfs/dummy/$file_name.txt"
echo 123456789a > "/mnt/bkpfs/dummy/$file_name.txt"
echo 123456789ab > "/mnt/bkpfs/dummy/$file_name.txt"

var=$(cat "/mnt/bkpfs/dummy/$file_name.txt")
if [ "$var" = "123456789ab" ]; then
	echo "continue"
else
	echo "Failed"
	exit 1
fi

cd ..

./bkpctl -r "1" "/mnt/bkpfs/dummy/$file_name.txt"

cd "/mnt/bkpfs/dummy/.bak.$file_name.txt"
var=$(cat "/mnt/bkpfs/dummy/$file_name.txt")
if [ "$var" = "123456789" ]; then
  echo "Succesful"
else
	echo "Failed"
fi

cd ~

umount /mnt/bkpfs
