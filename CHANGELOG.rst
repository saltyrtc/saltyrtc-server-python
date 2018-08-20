Changelog
*********

`2.0.1`_ (2018-08-20)
---------------------

- Fix to prevent creating two path instances with the same path string
- Various improvements to logging messages

`2.0.0`_ (2018-07-16)
---------------------

**Important:** Make sure you're using Python >= 3.4.4 and that your clients support the
`disconnected` message before upgrading.

- Add support for the `disconnected` message (major)
- Fix potential invalid order of messages when dispatching a `send-error`
- Fix the *id* field's value in the `send-error` message
- Fix a few potential race conditions

`1.0.2`_ (2017-11-15)
---------------------

- Fix do not accept unencrypted 'client-auth' messages from the initiator.

`1.0.1`_ (2017-07-25)
---------------------

- Fix to handle new `libnacl <https://github.com/saltstack/libnacl/pull/91>`_
  exceptions.

`1.0.0`_ (2017-03-24)
---------------------

- Add server implementation of the `SaltyRTC 1.0 Protocol`_
- Initial publication on PyPI

.. _SaltyRTC 1.0 Protocol: https://github.com/saltyrtc/saltyrtc-meta/blob/protocol-1.0/Protocol.md

.. _2.0.1: https://github.com/saltyrtc/saltyrtc-server-python/compare/v2.0.0...v2.0.1
.. _2.0.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/v1.0.2...v2.0.0
.. _1.0.2: https://github.com/saltyrtc/saltyrtc-server-python/compare/v1.0.1...v1.0.2
.. _1.0.1: https://github.com/saltyrtc/saltyrtc-server-python/compare/v1.0.0...v1.0.1
.. _1.0.0: https://github.com/saltyrtc/saltyrtc-server-python/compare/aa3aceba46cc8683e640499936a6eaa406819ef8...v1.0.0
