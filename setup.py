import ast
import os

from setuptools import setup, find_packages


def get_version():
    path = os.path.join(os.path.dirname(__file__), 'saltyrtc/__init__.py')
    with open(path) as file:
        for line in file:
            if line.startswith('__version__'):
                _, value = line.split('=', maxsplit=1)
                return ast.literal_eval(value.strip())

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))
# Import long description
long_description = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

setup(
    name='saltyrtc',
    version=get_version(),
    packages=find_packages(),
    install_requires=[
        'streql>=3.0.2',
        'libnacl>=1.4.4',
        'click>=6.3',
        'websockets>=3.0',
        'u-msgpack-python>=2.1',
        'asyncio>=3.4.3',
    ],
    tests_require=[
        'pytest>=2.8.7',
        'pytest-asyncio>=0.3.0',
    ],
    include_package_data=True,


    # PyPI metadata
    author='Lennart Grahl',
    author_email='lennart.grahl@gmail.com',
    description='A SaltyRTC compliant signalling client and server.',
    long_description=long_description,
    license='MIT License',
    keywords='webrtc ortc signalling signaling websocket websockets nacl',
    url='https://www.lgrahl.de/',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Security',
    ],
)