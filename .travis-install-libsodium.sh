#!/bin/bash
set -ev

if [ -d "${HOME}/libsodium/lib" ]; then
    exit 0;
fi

cd ${HOME}
git clone --depth 1 -b stable https://github.com/jedisct1/libsodium.git libsodium-git
cd libsodium-git
./autogen.sh
./configure --prefix=${HOME}/libsodium && make && make install

exit 0;
