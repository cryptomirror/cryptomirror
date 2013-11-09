#!/bin/sh
#
# Converts randombytes.o and libnacl.a
# into a useable libnacl.dylib 
#
mkdir tmp
cp randombytes.o libnacl.a tmp/
cd tmp/
ar -x libnacl.a
rm *wrapper*
clang -shared *.o -o libnacl.dylib
cp libnacl.dylib ../
cd ..
rm -rf tmp

