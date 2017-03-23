#!/bin/bash
set -ev

PYPY_NAME="pypy3.5-5.7-beta-linux_x86_64-portable"
PYPY_PATH="${HOME}/pypy"

wget https://bitbucket.org/squeaky/portable-pypy/downloads/${PYPY_NAME}.tar.bz2
tar -jxf ${PYPY_NAME}.tar.bz2
mv ${PYPY_NAME} pypy
echo 'Setting up aliases...'
ln -s ${HOME}/pypy/bin/pypy3.5 ${HOME}/pypy/bin/python
which python
python --version

echo 'Setting up pip...'
python -m ensurepip
which pip
pip --version

exit 0;
