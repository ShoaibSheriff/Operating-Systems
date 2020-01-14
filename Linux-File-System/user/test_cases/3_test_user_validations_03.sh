#!/bin/sh
echo "<-- test userland validations : Two options -->"
echo "<-- expected result : Script fails -->"

cd ..
./bkpctl -d -l "abc"
