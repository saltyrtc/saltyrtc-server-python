import socket
import asyncio
import os
import functools
import ssl

import pytest
import websockets
import umsgpack
import libnacl.public

import saltyrtc

from contextlib import closing


def pytest_namespace():
    return {'saltyrtc': {
        'ip': '127.0.0.1',
        'cert': os.path.normpath(
            os.path.join(os.path.abspath(__file__), os.pardir, 'cert.pem')),
    }}


def unused_tcp_port():
    """
    Find an unused localhost TCP port from 1024-65535 and return it.
    """
    with closing(socket.socket()) as sock:
        sock.bind((pytest.saltyrtc.ip, 0))
        return sock.getsockname()[1]


def key_pair():
    """
    Return a NaCl key pair.
    """
    return libnacl.public.SecretKey()


def key_path(key_pair):
    """
    Return the hexadecimal key path from a key pair using the public
    key.

    Arguments:
        - `key_pair`: A :class:`libnacl.public.SecretKey` instance.
    """
    return key_pair.hex_pk().decode()


@pytest.fixture(scope='module')
def event_loop(request):
    """
    Create an instance of the default event loop.
    """
    policy = asyncio.get_event_loop_policy()
    policy.get_event_loop().close()
    _event_loop = policy.new_event_loop()
    policy.set_event_loop(_event_loop)
    request.addfinalizer(_event_loop.close)
    return _event_loop


@pytest.fixture(scope='module')
def port():
    return unused_tcp_port()


@pytest.fixture(scope='module')
def url(port):
    """
    Return the URL where the server can be reached.
    """
    return 'wss://{}:{}'.format(pytest.saltyrtc.ip, port)


@pytest.fixture(scope='module')
def server_key():
    """
    Return a server NaCl key pair to be used by the server only.
    """
    return key_pair()


@pytest.fixture(scope='module')
def client_key():
    """
    Return a client NaCl key pair to be used by the client only.
    """
    return key_pair()


@pytest.fixture(scope='module')
def server(request, event_loop, port):
    """
    Return a :class:`saltyrtc.Server` instance.
    """
    coroutine = saltyrtc.serve(
        saltyrtc.util.create_ssl_context(pytest.saltyrtc.cert),
        host=pytest.saltyrtc.ip,
        port=port,
        loop=event_loop
    )
    server_ = event_loop.run_until_complete(coroutine)

    def fin():
        server_.close()
        event_loop.run_until_complete(server_.wait_closed())

    request.addfinalizer(fin)


@pytest.fixture(scope='module')
def ws_client_factory(client_key, url, event_loop, server):
    """
    Return a simplified :class:`websockets.client.connect` wrapper
    where no parameters are required.
    """
    # Note: The `server` argument is only required to fire up the server.

    # Create SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile=pytest.saltyrtc.cert)

    # Return partial
    return functools.partial(
        websockets.connect,
        '{}/{}'.format(url, key_path(client_key)),
        ssl=ssl_context,
        loop=event_loop,
    )


@pytest.fixture(scope='module')
def get_unencrypted_packet(event_loop):
    @asyncio.coroutine
    def _get_unencrypted_packet(client, timeout=0.1):
        data = yield from asyncio.wait_for(client.recv(), timeout, loop=event_loop)
        receiver = data[0]
        message = umsgpack.unpackb(data[1:])
        return receiver, message
    return _get_unencrypted_packet
