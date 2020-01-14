#!/bin/sh
# mount and create file on bkps file system
# expected result : Script succeeds - Backup folder should be created
set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

mount -t bkpfs -o maxver=5 /test/bkpfs /mnt/bkpfs

echo 12345678 > "/mnt/bkpfs/dummy/a.txt"
cd "/mnt/bkpfs/dummy/.bak.a.txt"
cd ~

umount /mnt/bkpfs
