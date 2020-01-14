#!/bin/sh
# test mount with suitable options provided
# Expected result : pass
set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

mount -t bkpfs -o maxver=5 /test/bkpfs /mnt/bkpfs

umount /mnt/bkpfs