#!/bin/sh
echo "<-- mount and create files on bkps file system -->"
echo "<-- expected result : Script fails - Should only maintain appropriate number of backup files -->"
# set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

max_bkps=$(( ( RANDOM % 10 )  + 1 ))
file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o "maxver=$max_bkps" /test/bkpfs /mnt/bkpfs

 while [  $max_bkps -gt 0 ]; do
     echo 123456789a > "/mnt/bkpfs/dummy/$file_name.txt"
     let max_bkps=max_bkps-1 
 done

echo 123456789abcde > "/mnt/bkpfs/dummy/$file_name.txt"

cd "/mnt/bkpfs/dummy/.bak.$file_name.txt"

var=$(cat 1)
cd ~

umount /mnt/bkpfs
