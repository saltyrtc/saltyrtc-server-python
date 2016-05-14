import socket
import asyncio
import os
import ssl
import struct

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
        'subprotocols': [
            saltyrtc.SubProtocol.saltyrtc_v1_0.value
        ],
        'timeout': 0.01,
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


def _cookie():
    """
    Return a random cookie for the client.
    """
    return os.urandom(16)


@asyncio.coroutine
def _sleep(timeout=None):
    """
    Sleep *timeout* seconds.
    """
    if timeout is None:
        timeout = pytest.saltyrtc.timeout
    yield from asyncio.sleep(timeout)


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
def sleep():
    """
    Sleep *timeout* seconds.
    """
    return _sleep


@pytest.fixture(scope='module')
def cookie():
    """
    Return a random cookie for the client.
    """
    return _cookie()


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


class Client:
    def __init__(self, ws_client, pack_message, unpack_message, timeout=0.1):
        self.ws_client = ws_client
        self.pack_and_send = pack_message
        self.recv_and_unpack = unpack_message
        self.timeout = timeout
        self.session_key = None
        self.box = None

    def send(self, receiver, message, nonce=None):
        yield from self.pack_and_send(
            self.ws_client, receiver, message,
            nonce=nonce, box=self.box, timeout=self.timeout
        )

    def recv(self):
        return (yield from self.recv_and_unpack(
            self.ws_client,
            box=self.box, timeout=self.timeout
        ))


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

    def _ws_client_factory(path=None, **kwargs):
        if path is None:
            path = '{}/{}'.format(url, key_path(client_key))
        _kwargs = {
            'subprotocols': pytest.saltyrtc.subprotocols,
            'ssl': ssl_context,
            'loop': event_loop,
        }
        _kwargs.update(kwargs)
        return websockets.connect(path, **_kwargs)
    return _ws_client_factory


@pytest.fixture(scope='module')
def client_factory(client_key, url, event_loop, server, pack_message, unpack_message):
    """
    Return a simplified :class:`websockets.client.connect` wrapper
    where no parameters are required.
    """
    # Note: The `server` argument is only required to fire up the server.

    # Create SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile=pytest.saltyrtc.cert)

    @asyncio.coroutine
    def _client_factory(path=client_key, timeout=0.1, **kwargs):
        _kwargs = {
            'subprotocols': pytest.saltyrtc.subprotocols,
            'ssl': ssl_context,
            'loop': event_loop,
        }
        _kwargs.update(kwargs)
        ws_client = yield from websockets.connect(
            '{}/{}'.format(url, key_path(path)),
            **_kwargs
        )
        return Client(
            ws_client, pack_message, unpack_message,
            timeout=timeout
        )
    return _client_factory


@pytest.fixture(scope='module')
def unpack_message(event_loop):
    @asyncio.coroutine
    def _unpack_message(client, box=None, timeout=0.1):
        data = yield from asyncio.wait_for(client.recv(), timeout, loop=event_loop)
        receiver = data[0]
        data = data[1:]
        if box is not None:
            nonce = data[:16]
            data = box.decrypt(data[16:], nonce=nonce)
        else:
            nonce = None
        message = umsgpack.unpackb(data)
        return receiver, message, nonce
    return _unpack_message


@pytest.fixture(scope='module')
def pack_message(event_loop):
    @asyncio.coroutine
    def _pack_message(client, receiver, message, nonce=None, box=None, timeout=0.1):
        receiver = struct.pack('!B', receiver)
        data = umsgpack.packb(message)
        if box is not None:
            assert nonce is not None
            data = box.encrypt(data, nonce=nonce)
        data = b''.join((receiver, data))
        yield from asyncio.wait_for(client.send(data), timeout, loop=event_loop)
    return _pack_message
