#!/bin/sh
# test mount with no options provided
# Expected result : fails
set -x
mkdir -p /test/bkpfs/dummy
mkdir -p /mnt/bkpfs

mount -t bkpfs /test/bkpfs /mnt
