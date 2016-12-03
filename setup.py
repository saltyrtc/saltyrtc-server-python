import ast
import os
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
py_version = sys.version_info[:2]
if py_version < (3, 4):
    raise Exception("SaltyRTC requires Python >= 3.4")

# Logging requirements
logging_require = [
    'logbook>=1.0.0,<2',
]

# Test requirements
# Note: These are just tools that aren't required, so a version range
#       is not necessary here.
tests_require = [
    'pytest>=3.0.2',
    'pytest-asyncio>=0.5.0',
    'pytest-cov>=2.3.1',
    'flake8>=3.0.4',
    'isort>=4.2.5',
    'collective.checkdocs>=0.2',
    'Pygments>=2.1.3',  # required by checkdocs
] + logging_require

setup(
    name='saltyrtc.server',
    version=get_version(),
    packages=['saltyrtc', 'saltyrtc.server'],
    install_requires=[
        'libnacl>=1.5.0,<2',
        'click>=6.6',  # doesn't seem to follow semantic versioning
        'websockets>=3.2,<4',
        'u-msgpack-python>=2.2,<3',
    ],
    tests_require=tests_require,
    extras_require={
        ':python_version<="3.4"': ['asyncio>=3.4.3'],
        'dev': tests_require,
        'logging': logging_require,
        'uvloop': ['uvloop>=0.5.3'],
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
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Security',
    ],
)
