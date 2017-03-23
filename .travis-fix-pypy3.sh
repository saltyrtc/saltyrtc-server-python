#!/bin/bash
set -ev

PY_VERSION="3.5"
PYPY_NAME="pypy${PY_VERSION}-5.7-beta-linux_x86_64-portable"

echo "Unpacking PyPy ${PY_VERSION}"
wget https://bitbucket.org/squeaky/portable-pypy/downloads/${PYPY_NAME}.tar.bz2
tar -jxf ${PYPY_NAME}.tar.bz2

echo 'Creating virtual environment'
${PYPY_NAME}/bin/pypy${PY_VERSION} -m venv ${HOME}/pypy

exit 0;
