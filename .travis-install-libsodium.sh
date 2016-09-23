#!/bin/bash
set -ev

if [ -d "${HOME}/libsodium" ]; then
    exit 0;
fi

git clone --depth 1 -b stable https://github.com/jedisct1/libsodium.git
cd libsodium
./autogen.sh
./configure --prefix=${HOME}/libsodium && make && make install
cd ..

exit 0;
