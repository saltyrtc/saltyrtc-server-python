#!/bin/bash
set -ev

PY_VERSION="3.5"
PYPY_NAME="pypy${PY_VERSION}-5.7-beta-linux_x86_64-portable"

wget https://bitbucket.org/squeaky/portable-pypy/downloads/${PYPY_NAME}.tar.bz2
tar -jxf ${PYPY_NAME}.tar.bz2
mv ${PYPY_NAME} ${HOME}/pypy
echo 'Setting up aliases...'
export PATH=${HOME}/pypy/bin:${PATH}
ln -s ${HOME}/pypy/bin/pypy${PY_VERSION} ${HOME}/pypy/bin/python
which python
python --version

echo 'Setting up pip...'
python -m ensurepip
ln -s ${HOME}/pypy/bin/pip{PY_VERSION} ${HOME}/pypy/bin/pip
ls -l ${HOME}/pypy/bin
which pip
pip --version

exit 0;
