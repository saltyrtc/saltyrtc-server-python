import ast
import os
import platform
import sys
from setuptools import setup


def get_version():
    path = os.path.join(os.path.dirname(__file__), 'saltyrtc', 'server', '__init__.py')
    with open(path) as file:
        for line in file:
            if line.startswith('__version__'):
                _, value = line.split('=', maxsplit=1)
                return ast.literal_eval(value.strip())
        else:
            raise Exception('Version not found in {}'.format(path))


def read(file):
    return open(os.path.join(os.path.dirname(__file__), file)).read().strip()


# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Import long description
long_description = '\n\n'.join((read('README.rst'), read('CHANGELOG.rst')))

# Check python version
py_version = sys.version_info[:3]
if py_version < (3, 6, 1):
    raise Exception("SaltyRTC requires Python >= 3.6.1")

# Logging requirements
logging_require = [
    'logbook>=1.0.0,<2',
]

# mypy currently does not run on pypy (tested with pypy3 6.0.0)
if platform.python_implementation() == 'PyPy':
    mypy_require = []
else:
    mypy_require = [
        'mypy==0.780',
    ]

# Test requirements
# Note: These are just tools that aren't required, so a version range
#       is not necessary here.
tests_require = [
    'pytest>=3.10.1,<4',
    'pytest-asyncio>=0.9.0,<0.10',
    'pytest-cov>=2.9.0,<3',
    'pytest-mock>=1.13.0,<2',
    'flake8==4.0.1',
    'isort==5.10.1',
    'collective.checkdocs>=0.2',
    'Pygments>=2.11.2,<3',  # required by checkdocs
    'ordered-set>=4.0.2,<5',  # required by TestServer class
] + logging_require + mypy_require

setup(
    name='saltyrtc.server',
    version=get_version(),
    packages=['saltyrtc', 'saltyrtc.server'],
    package_data={'saltyrtc.server': ['py.typed']},
    install_requires=[
        'libnacl>=1.5.0,<2',
        'click>=8.0.4,<9',  # doesn't seem to follow semantic versioning (see #57)
        'websockets>=8.0,<9',
        'u-msgpack-python>=2.3,<3',
    ],
    tests_require=tests_require,
    extras_require={
        'dev': tests_require,
        'logging': logging_require,
        'uvloop': ['uvloop>=0.8.0,<2'],
    },
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'saltyrtc-server = saltyrtc.server.bin:main',
        ],
    },

    # PyPI metadata
    author='Lennart Grahl',
    author_email='lennart.grahl@gmail.com',
    description='A SaltyRTC compliant signalling server.',
    long_description=long_description,
    license='MIT',
    keywords='saltyrtc signalling signaling websocket websockets nacl',
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
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Security',
    ],
)
