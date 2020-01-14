#!/bin/sh
echo "<-- test userland validations -->"
echo "<-- expected result : Script fails -->"

mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

max_bkps=$(( ( RANDOM % 10 )  + 1 ))
file_name=$(( ( RANDOM % 10000 )  + 1 ))

mount -t bkpfs -o "maxver=$max_bkps" /test/bkpfs /mnt/bkpfs

cd ..
./bkpctl -l "/mnt/bkpfs/dummy/$file_name.txt"

cd ~

umount /mnt/bkpfs
