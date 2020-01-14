#!/bin/sh
echo "<-- mount and create file on bkps file system -->"
echo "<-- expected result : Script fails - Old copy should not be overwritten -->"

mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o maxver=5 /test/bkpfs /mnt/bkpfs

echo 123456789 > "/mnt/bkpfs/dummy/$file_name.txt"
echo abcdefghi > "/mnt/bkpfs/dummy/$file_name.txt"

cd "/mnt/bkpfs/dummy/.bak.$file_name.txt"
var=$(cat 1)
if [ "$var" = "123456789" ]; then
  echo "Succesful"
else
	echo "Failed"
fi
cd ~
umount /mnt/bkpfs
