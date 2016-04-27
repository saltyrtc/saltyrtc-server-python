# SaltyRTC Signalling Server

This is an implementation of the SaltyRTC Signalling Server which allows end-to-end
encrypted signalling for WebRTC and ORTC.

## Note

On machines where Python 3 is not the default Python runtime, you should use
``pip3`` instead of ``pip``.

## Prerequisites

```
$ sudo apt-get install python3 python3-pip
```

We recommend using the [virtualenv](https://virtualenv.readthedocs.org/en/latest/)
package to create an isolated Python environment:

```
$ sudo pip install virtualenv
$ virtualenv -p python3 saltyrtc-server-venv
```

You can switch into the created virtual environment *saltyrtc-server-venv*
by running this command:

```
$ source saltyrtc-server-venv/bin/activate
```

To deactivate the virtual environment, just run:

```
$ deactivate
```

## Installation

If you are using a virtual environment, activate it first.

Install the module by running:

```
$ pip install git+https://github.com/saltyrtc/saltyrtc-server-python.git
```

The dependency ``libnacl`` will be installed automatically. However, you may need to
[install ``libsodium``](https://download.libsodium.org/doc/installation/index.html) for ``libnacl``
to work. 

## Command Line Usage

TODO
