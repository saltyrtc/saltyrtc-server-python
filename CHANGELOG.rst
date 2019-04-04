Changelog
*********

`4.1.0`_ (2019-04-04)
---------------------

- Allow the use of environment variables as CLI parameter substitution
    - Instead of ``saltyrtc-server serve --tlskey=foo`` you can now write
      ``SALTYRTC_SERVER_TLSKEY=foo saltyrtc-server serve``
- Fix import order in pyi files

`4.0.1`_ (2019-01-24)
---------------------

- Bump the Python version requirement to 3.5.3
- Remove workarounds for Python 3.5.2

`4.0.0`_ (2018-01-24)
---------------------

**Important:** Make sure you're using Python >= 3.5.3 before upgrading.

- Drop Python 3.4 support (major)
- Deprecate the CLI options `-sc`, `--sslcert` and `-sk`, `--sslkey`. Use
  `-tc`, `--tlscert` and `-tk`, `--tlskey` instead.
- Add type hints
- Fix discard string messages
- Fix validate received client ID types correctly
- Fix validate received sub-protocols correctly
- Fix a race condition during the handshake when one client drops another
- Cleanup of the code base

`3.1.2`_ (2019-01-08)
---------------------

- Fix imports for earlier Python 3.5 versions

`3.1.1`_ (2019-01-08)
---------------------

- Disable deprecation warning in py.test for now (see `#90`_)

`3.1.0`_ (2019-01-07)
---------------------

- Event callback arguments now always need to provide a `data` argument

`3.0.1`_ (2019-01-02)
---------------------

- Fix forward the `timeout` close code as an `int` to event callbacks

`3.0.0`_ (2018-12-18)
---------------------

- Use the `timeout` close code (`3008`) when a client does not respond to a
  *ping* message (major)
- Add support for Python 3.7
- Various task queue improvements resulting in more robust client handling
- Fix to not send a 'disconnected' message when a responder has been dropped
  via 'drop-responder'
- Fix to prevent the initiator from relaying messages to a responder client
  which is in the process of being dropped
- Fix to not accept new incoming connections when closing the server

`2.0.1`_ (2018-08-20)
---------------------

- Fix to prevent creating two path instances with the same path string
- Various improvements to logging messages

`2.0.0`_ (2018-07-16)
---------------------

**Important:** Make sure you're using Python >= 3.4.4 and that your clients
support the `disconnected` message before upgrading.

- Add support for the `disconnected` message (major)
- Fix potential invalid order of messages when dispatching a `send-error`
- Fix the *id* field's value in the `send-error` message
- Fix a few potential race conditions

`1.0.2`_ (2017-11-15)
---------------------

- Fix do not accept unencrypted 'client-auth' messages from the initiator

`1.0.1`_ (2017-07-25)
---------------------

- Fix to handle new `libnacl <https://github.com/saltstack/libnacl/pull/91>`_
  exceptions

`1.0.0`_ (2017-03-24)
---------------------

- Add server implementation of the `SaltyRTC 1.0 Protocol`_
- Initial publication on PyPI

.. _#90: https://github.com/saltyrtc/saltyrtc-server-python/issues/90
.. _SaltyRTC 1.0 Protocol: https://github.com/saltyrtc/saltyrtc-meta/blob/protocol-1.0/Protocol.md

.. _4.1.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/v4.0.1...v4.1.0
.. _4.0.1: https://github.com/saltyrtc/saltyrtc-server-python/compare/v4.0.0...v4.0.1
.. _4.0.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/v3.1.2...v4.0.0
.. _3.1.2: https://github.com/saltyrtc/saltyrtc-server-python/compare/v3.1.1...v3.1.2
.. _3.1.1: https://github.com/saltyrtc/saltyrtc-server-python/compare/v3.1.0...v3.1.1
.. _3.1.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/v3.0.1...v3.1.0
.. _3.0.1: https://github.com/saltyrtc/saltyrtc-server-python/compare/v3.0.0...v3.0.1
.. _3.0.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/v2.0.1...v3.0.0
.. _2.0.1: https://github.com/saltyrtc/saltyrtc-server-python/compare/v2.0.0...v2.0.1
.. _2.0.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/v1.0.2...v2.0.0
.. _1.0.2: https://github.com/saltyrtc/saltyrtc-server-python/compare/v1.0.1...v1.0.2
.. _1.0.1: https://github.com/saltyrtc/saltyrtc-server-python/compare/v1.0.0...v1.0.1
.. _1.0.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/aa3aceba46cc8683e640499936a6eaa406819ef8...v1.0.0
