#!/bin/bash -e

OPENSSL_VERSION="3.0.0"

mkdir -p deps
mkdir -p deps/include
mkdir -p deps/lib

mkdir -p build && cd build

wget --no-check-certificate https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz -O openssl-${OPENSSL_VERSION}.tar.gz
tar -xzf openssl-${OPENSSL_VERSION}.tar.gz

cd openssl-${OPENSSL_VERSION}
./config -no-shared -no-asm -no-zlib -no-comp -no-dgram -no-filenames -no-cms
make -j$((`nproc --all`*2))
cp -fr include ../../deps
cp libcrypto.a ../../deps/lib
cp libssl.a ../../deps/lib
cd ..
