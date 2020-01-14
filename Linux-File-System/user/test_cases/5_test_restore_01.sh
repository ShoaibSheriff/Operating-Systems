#!/bin/sh
echo "<-- restore files - simple command -->"
echo "<-- successful with output -->"
# set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

max_bkps=$(( ( RANDOM % 10 )  + 1 ))
file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o "maxver=$max_bkps" /test/bkpfs /mnt/bkpfs

echo 123456789a > "/mnt/bkpfs/dummy/$file_name.txt"

cd ..
./bkpctl -r "1" "/mnt/bkpfs/dummy/$file_name.txt"

if [ "$?" -eq 0 ]; then
  echo "Succesful"
else
	echo "Failed"
fi

umount /mnt/bkpfs
