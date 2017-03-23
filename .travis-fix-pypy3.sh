#!/bin/bash
set -ev

PYPY_NAME="pypy3.5-5.7-beta-linux_x86_64-portable"
PYPY_PATH="${HOME}/${PYPY_NAME}"

if [ "$TRAVIS_PYTHON_VERSION" = 'pypy3' ]; then
    deactivate
    wget https://bitbucket.org/squeaky/portable-pypy/downloads/${PYPY_NAME}.tar.bz2
    tar -jxf ${PYPY_NAME}.tar.bz2
    echo 'Setting up aliases...'
    ln -s ${PYPY_PATH}/bin/pypy3.5 ${PYPY_PATH}/bin/python
    export PATH=${PYPY_PATH}/bin:${PATH}
    which python
    python --version

    echo 'Setting up pip...'
    python -m ensurepip
    which pip
    pip --version
fi
