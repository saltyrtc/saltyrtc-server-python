#!/bin/bash
set -ev

PY_VERSION="3.5"
PYPY_NAME="pypy${PY_VERSION}-5.7-beta-linux_x86_64-portable"

echo "Unpacking PyPy ${PY_VERSION}"
wget https://bitbucket.org/squeaky/portable-pypy/downloads/${PYPY_NAME}.tar.bz2 -O ${HOME}/pypy.tar.bz2
tar -jxf ${HOME}/pypy.tar.bz2 -C ${HOME}
mv ${HOME}/${PYPY_NAME} ${HOME}/pypy

echo 'Creating virtual environment'
${HOME}/pypy/bin/pypy${PY_VERSION} -m venv ${HOME}/venv

exit 0;
