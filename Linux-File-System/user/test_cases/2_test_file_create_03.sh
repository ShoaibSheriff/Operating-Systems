#!/bin/sh
# mount and create file on bkps file system
# expected result : Script succeeds - New Backup file should be created with copy
set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o maxver=5 /test/bkpfs /mnt/bkpfs
echo 123456 > "/mnt/bkpfs/dummy/$file_name.txt"
echo abcdef > "/mnt/bkpfs/dummy/$file_name.txt"

cd "/mnt/bkpfs/dummy/.bak.$file_name.txt"
var=$(cat 2)
echo $var
if [ "$var" = "abcdef" ]; then
  echo "File back up succesful"
else
	echo "File backup failed"
fi
cd ~

umount /mnt/bkpfs