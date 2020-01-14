#!/bin/sh
echo "<-- test userland validations : Unknown validation -->"
echo "<-- expected result : Script fails -->"

cd ..
./bkpctl -x
