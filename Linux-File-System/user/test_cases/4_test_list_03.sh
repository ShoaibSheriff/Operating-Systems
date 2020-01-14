#!/bin/sh
echo "<-- list files for 3 backup versions -->"
echo "<-- successful with expected output -->"
# set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

max_bkps=$(( ( RANDOM % 10 )  + 1 ))
file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o "maxver=$max_bkps" /test/bkpfs /mnt/bkpfs

echo 123456789a > "/mnt/bkpfs/dummy/$file_name.txt"
echo 123456789ab > "/mnt/bkpfs/dummy/$file_name.txt"
echo 123456789abc > "/mnt/bkpfs/dummy/$file_name.txt"

cd ..


var=$(./bkpctl -l "/mnt/bkpfs/dummy/$file_name.txt")
if [ "$var" = "Backup versions available are : 3, 2, 1" ]; then
  echo "Succesful"
else
	echo "Failed"
fi


umount /mnt/bkpfs
