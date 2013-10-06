You'll need the NaCl builds of 'libnacl.a' and 'randombytes.o'.

To build these grab: (reproduced here)
nacl-20110221.tar.bz2  - SHA256 - 4f277f89735c8b0b8a6bbd043b3efb3fa1cc68a9a5da6a076507d067fc3b3bf8

tar -xjf nacl-20110221.tar.bz2
cd nacl-20110221
./do

The builds will be placed under
libs/nacl/lib/amd64/
