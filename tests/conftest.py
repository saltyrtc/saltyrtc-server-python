import socket
import asyncio
import os
import ssl
import struct

import pytest
import websockets
import umsgpack
import libnacl.public
import logbook

import saltyrtc

from contextlib import closing


def pytest_namespace():
    return {'saltyrtc': {
        'ip': '127.0.0.1',
        'port': 8766,
        'external_server': False,
        'cert': os.path.normpath(
            os.path.join(os.path.abspath(__file__), os.pardir, 'cert.pem')),
        'subprotocols': [
            saltyrtc.SubProtocol.saltyrtc_v1.value
        ],
        'debug': True,
        'timeout': 0.05,
    }}


def unused_tcp_port():
    """
    Find an unused localhost TCP port from 1024-65535 and return it.
    """
    if pytest.saltyrtc.debug or pytest.saltyrtc.external_server:
        return pytest.saltyrtc.port
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


def _get_timeout(timeout):
    """
    Return the defined timeout. In case 'debug' has been activated,
    the timeout will be multiplied by 10.
    """
    if timeout is None:
        timeout = pytest.saltyrtc.timeout
        if pytest.saltyrtc.debug:
            timeout *= 10
    return timeout


@asyncio.coroutine
def _sleep(timeout=None):
    """
    Sleep *timeout* seconds.
    """
    yield from asyncio.sleep(_get_timeout(timeout))


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
def initiator_key():
    """
    Return a client NaCl key pair to be used by the initiator only.
    """
    return key_pair()


@pytest.fixture(scope='module')
def responder_key():
    """
    Return a client NaCl key pair to be used by the responder only.
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
    if pytest.saltyrtc.debug:
        # Enable asyncio debug logging
        os.environ['PYTHONASYNCIODEBUG'] = '1'

        # Enable logging
        saltyrtc.util.enable_logging(level=logbook.TRACE, redirect_loggers={
            'asyncio': logbook.DEBUG,
            'websockets': logbook.DEBUG,
        })

        # Push handler
        logging_handler = logbook.StderrHandler()
        logging_handler.push_application()

    # Setup server
    if not pytest.saltyrtc.external_server:
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
            if pytest.saltyrtc.debug:
                logging_handler.pop_application()

        request.addfinalizer(fin)
        return server_


class _DefaultBox:
    pass


class Client:
    def __init__(self, ws_client, pack_message, unpack_message, timeout=None):
        self.ws_client = ws_client
        self.pack_and_send = pack_message
        self.recv_and_unpack = unpack_message
        self.timeout = _get_timeout(timeout)
        self.session_key = None
        self.box = None

    def send(self, nonce, message, box=_DefaultBox, timeout=None):
        if timeout is None:
            timeout = self.timeout
        return (yield from self.pack_and_send(
            self.ws_client, nonce, message,
            box=self.box if box == _DefaultBox else box, timeout=timeout
        ))

    def recv(self, box=_DefaultBox, timeout=None):
        if timeout is None:
            timeout = self.timeout
        return (yield from self.recv_and_unpack(
            self.ws_client,
            box=self.box if box == _DefaultBox else box, timeout=timeout
        ))

    def close(self):
        return self.ws_client.close()


@pytest.fixture(scope='module')
def ws_client_factory(initiator_key, url, event_loop, server):
    """
    Return a simplified :class:`websockets.client.connect` wrapper
    where no parameters are required.
    """
    # Note: The `server` argument is only required to fire up the server.

    # Create SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile=pytest.saltyrtc.cert)
    if pytest.saltyrtc.debug:
        ssl_context.set_ciphers('RSA')

    def _ws_client_factory(path=None, **kwargs):
        if path is None:
            path = '{}/{}'.format(url, key_path(initiator_key))
        _kwargs = {
            'subprotocols': pytest.saltyrtc.subprotocols,
            'ssl': ssl_context,
            'loop': event_loop,
        }
        _kwargs.update(kwargs)
        return websockets.connect(path, **_kwargs)
    return _ws_client_factory


@pytest.fixture(scope='module')
def client_factory(
        initiator_key, url, event_loop, server, cookie, responder_key,
        pack_nonce, pack_message, unpack_message
):
    """
    Return a simplified :class:`websockets.client.connect` wrapper
    where no parameters are required.
    """
    # Note: The `server` argument is only required to fire up the server.
    cookie_ = cookie

    # Create SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile=pytest.saltyrtc.cert)
    if pytest.saltyrtc.debug:
        ssl_context.set_ciphers('RSA')

    @asyncio.coroutine
    def _client_factory(
            ws_client=None,
            path=initiator_key, timeout=None, cookie=cookie_,
            initiator_handshake=False, responder_handshake=False,
            **kwargs
    ):
        _kwargs = {
            'subprotocols': pytest.saltyrtc.subprotocols,
            'ssl': ssl_context,
            'loop': event_loop,
        }
        _kwargs.update(kwargs)
        if ws_client is None:
            ws_client = yield from websockets.connect(
                '{}/{}'.format(url, key_path(path)),
                **_kwargs
            )
        client = Client(
            ws_client, pack_message, unpack_message,
            timeout=timeout
        )

        if not initiator_handshake and not responder_handshake:
            return client

        # Do handshake
        key = initiator_key if initiator_handshake else responder_key

        # server-hello
        message, _, sck, s, d, start_scsn = yield from client.recv(timeout=timeout)

        cck, ccsn = cookie, 2 ** 32 - 1
        if responder_handshake:
            # client-hello
            yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
                'type': 'client-hello',
                'key': responder_key.pk,
            }, timeout=timeout)
            ccsn += 1

        # client-auth
        client.box = libnacl.public.Box(sk=key, pk=message['key'])
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': pytest.saltyrtc.subprotocols,
        }, timeout=timeout)
        ccsn += 1

        # server-auth
        message, _, ck, s, d, scsn = yield from client.recv(timeout=timeout)

        # Return client and additional data
        additional_data = {
            'id': d,
            'sck': sck,
            'start_scsn': start_scsn,
            'cck': cck,
            'ccsn': ccsn,
        }
        if initiator_handshake:
            additional_data['responders'] = message['responders']
        else:
            additional_data['initiator_connected'] = message['initiator_connected']
        return client, additional_data
    return _client_factory


@pytest.fixture(scope='module')
def unpack_message(event_loop):
    @asyncio.coroutine
    def _unpack_message(client, box=None, timeout=None):
        timeout = _get_timeout(timeout)
        data = yield from asyncio.wait_for(client.recv(), timeout, loop=event_loop)
        nonce = data[:saltyrtc.NONCE_LENGTH]
        (cookie,
         source, destination,
         combined_sequence_number) = struct.unpack(saltyrtc.NONCE_FORMATTER, nonce)
        combined_sequence_number, *_ = struct.unpack(
            '!Q', b'\x00\x00' + combined_sequence_number)
        data = data[saltyrtc.NONCE_LENGTH:]
        if box is not None:
            data = box.decrypt(data, nonce=nonce)
        else:
            nonce = None
        message = umsgpack.unpackb(data)
        return (
            message,
            nonce,
            cookie,
            source, destination,
            combined_sequence_number
        )
    return _unpack_message


@pytest.fixture(scope='module')
def pack_nonce():
    def _pack_nonce(cookie, source, destination, combined_sequence_number):
        return struct.pack(
            saltyrtc.NONCE_FORMATTER,
            cookie,
            source, destination,
            struct.pack('!Q', combined_sequence_number)[2:]
        )
    return _pack_nonce


@pytest.fixture(scope='module')
def pack_message(event_loop):
    @asyncio.coroutine
    def _pack_message(client, nonce, message, box=None, timeout=None):
        data = umsgpack.packb(message)
        if box is not None:
            _, data = box.encrypt(data, nonce=nonce, pack_nonce=False)
        data = b''.join((nonce, data))
        timeout = _get_timeout(timeout)
        yield from asyncio.wait_for(client.send(data), timeout, loop=event_loop)
        return data
    return _pack_message
