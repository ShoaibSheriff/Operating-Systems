#!/bin/sh
echo "<-- test userland validations : Unknown value -->"
echo "<-- expected result : Script fails -->"

cd ..
./bkpctl -d "abc" "/"
