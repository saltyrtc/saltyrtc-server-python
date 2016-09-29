SaltyRTC Signalling Server
==========================

|Travis| |codecov| |PyPI|

This is a SaltyRTC server implementation for Python 3.4+ using
`asyncio`_.

Note
****

On machines where Python 3 is not the default Python runtime, you should
use ``pip3`` instead of ``pip``.

Prerequisites
*************

.. code-block:: bash

    $ sudo apt-get install python3 python3-pip

We recommend using `venv`_ to create an isolated Python environment:

.. code-block:: bash

    $ pyvenv venv

You can switch into the created virtual environment *venv* by running
this command:

.. code-block:: bash

    $ source venv/bin/activate

While the virtual environment is active, all packages installed using
``pip`` will be installed into this environment.

To deactivate the virtual environment, just run:

.. code-block:: bash

    $ deactivate

If you want easier handling of your virtualenvs, you might also want to
take a look at `virtualenvwrapper`_.

Installation
************

If you are using a virtual environment, activate it first.

Install the module by running:

.. code-block:: bash

    $ pip install git+https://github.com/saltyrtc/saltyrtc-server-python.git

The dependency ``libnacl`` will be installed automatically. However, you
may need to `install ``libsodium```_ for ``libnacl`` to work.

Command Line Usage
******************

TODO

Documentation
*************

TODO

.. _asyncio: https://docs.python.org/3/library/asyncio.html
.. _venv: https://docs.python.org/3/library/venv.html
.. _virtualenvwrapper: https://virtualenvwrapper.readthedocs.io/
.. _install ``libsodium``: https://download.libsodium.org/doc/installation/index.html

.. |Travis| image:: https://travis-ci.org/saltyrtc/saltyrtc-server-python.svg?branch=master
   :target: https://travis-ci.org/saltyrtc/saltyrtc-server-python
.. |codecov| image:: https://codecov.io/gh/saltyrtc/saltyrtc-server-python/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/saltyrtc/saltyrtc-server-python
.. |PyPI| image:: https://badge.fury.io/py/saltyrtc.svg
   :target: https://badge.fury.io/py/saltyrtc
