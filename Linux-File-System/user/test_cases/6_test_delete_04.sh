#!/bin/sh
echo "<-- delete files - delete all, then try to list versions -->"
echo "<-- Fails as no backups exist -->"
# set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

max_bkps=$(( ( RANDOM % 10 )  + 2 ))
file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o "maxver=$max_bkps" /test/bkpfs /mnt/bkpfs

echo 123456789a > "/mnt/bkpfs/dummy/$file_name.txt"
echo 123456789ab > "/mnt/bkpfs/dummy/$file_name.txt"
echo 123456789abc > "/mnt/bkpfs/dummy/$file_name.txt"

cd ..
./bkpctl -d "a" "/mnt/bkpfs/dummy/$file_name.txt"

./bkpctl -l "/mnt/bkpfs/dummy/$file_name.txt"

if [ "$?" -eq 0 ]; then
  echo "Succesful"
else
	echo "Failed"
fi

umount /mnt/bkpfs
