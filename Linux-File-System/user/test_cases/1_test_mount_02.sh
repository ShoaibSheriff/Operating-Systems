#!/bin/sh
# test mount with incorrect options
# Expected result : fails
set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

mount -t bkpfs -o maxver=abc /test/bkpfs /mnt/bkpfs
