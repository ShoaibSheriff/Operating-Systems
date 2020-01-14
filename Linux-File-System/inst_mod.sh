#!/bin/sh
#
umount /test/mnt/bkpfs

rmmod bkpfs
insmod bkpfs.ko
lsmod

mount -t bkpfs -o maxver=2 /test/hw2 /test/mnt/bkpfs
