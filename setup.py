import ast
import os
import sys

from setuptools import setup


def get_version():
    path = os.path.join(os.path.dirname(__file__), 'saltyrtc/__init__.py')
    with open(path) as file:
        for line in file:
            if line.startswith('__version__'):
                _, value = line.split('=', maxsplit=1)
                return ast.literal_eval(value.strip())


def read(file):
    return open(os.path.join(os.path.dirname(__file__), file)).read().strip()

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Import long description
long_description = '\n\n'.join((read('README.rst'), read('CHANGELOG.rst')))

# Check python version
py_version = sys.version_info[:2]
if py_version < (3, 4):
    raise Exception("SaltyRTC requires Python >= 3.4")

# Test requirements
tests_require = [
    'pytest>=3.0.2',
    'pytest-asyncio>=0.5.0',
    'pytest-cov>=2.3.1',
    'logbook>=1.0.0',
    'flake8>=3.0.4',
    'isort>=4.2.5',
    'collective.checkdocs>=0.2',
    'Pygments>=2.1.3'  # required by checkdocs
],

setup(
    name='saltyrtc',
    version=get_version(),
    packages=['saltyrtc'],
    install_requires=[
        'libnacl>=1.5.0',
        'click>=6.6',
        'websockets>=3.2',
        'u-msgpack-python>=2.2',
    ],
    tests_require=tests_require,
    extras_require={
        ':python_version<="3.4"': ['asyncio>=3.4.3'],
        'test': tests_require,
        'logging': ['logbook>=1.0.0'],
        'uvloop': ['uvloop>=0.5.3'],
    },
    include_package_data=True,

    # PyPI metadata
    author='Lennart Grahl',
    author_email='lennart.grahl@gmail.com',
    description='A SaltyRTC compliant signalling server.',
    long_description=long_description,
    license='MIT',
    keywords='saltyrtc webrtc ortc signalling signaling websocket websockets nacl',
    url='https://github.com/saltyrtc/saltyrtc-server-python',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Security',
    ],
)
