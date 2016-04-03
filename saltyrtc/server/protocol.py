import asyncio
import os

import websockets
import libnacl.public

from saltyrtc.server import util
from .exception import *
from .common import KEY_LENGTH, ReceiverType, MessageType
from .message import unpack, ServerHelloMessage


class Path:
    __slots__ = ('log', 'initiator', 'responder')

    def __init__(self, path):
        self.log = util.get_logger('path.{}'.format(path))
        self.initiator = None
        self.responder = {
            0x02: None,
            0x03: None,
        }


class Client:
    __slots__ = ('_connection', '_key', '_box', 'type', 'authenticated')

    def __init__(self, connection, secret_key=None):
        self._connection = connection
        self._key = secret_key
        self._box = None
        self.type = None
        self.authenticated = False

    @property
    def key(self):
        """
        Return the :class:`libnacl.public.SecretKey` instance.
        """
        if self._key is None:
            self._key = libnacl.public.SecretKey()
        return self._key

    @property
    def box_ready(self):
        """
        Return `True` if keys have been exchanged and only encrypted
        payloads must be accepted.
        """
        return self._box is not None

    @property
    def box(self):
        """
        Return the :class:`libnacl.public.Box` instance.

        Raises :exc:`ValueError` in case no box has been set, yet.
        """
        if self.box is None:
            raise ValueError('Box has not been set, yet')
        return self._box

    @box.setter
    def box(self, public_key):
        """Set the :class:`libnacl.public.Box` instance."""
        self.box = libnacl.public.Box(self.key, public_key)

    def p2p_allowed(self, receiver_type):
        """
        Return `True` if :class:`RawMessage` instances are allowed and
        can be sent to the requested :class:`ReceiverType`.
        """
        return not self.authenticated or self.type is None or self.type == receiver_type

    @asyncio.coroutine
    def send(self, message):
        """
        Disconnected
        """
        # Pack message
        data = message.pack(self)

        # Send data
        try:
            yield from self._connection.send(data)
        except websockets.ConnectionClosed as exc:
            raise Disconnected() from exc

    @asyncio.coroutine
    def receive(self):
        """
        Disconnected
        """
        # Receive data
        try:
            data = yield from self._connection.recv()
        except websockets.ConnectionClosed as exc:
            raise Disconnected() from exc

        # Unpack data and return
        return unpack(self, data)


class Protocol:
    PATH_LENGTH = KEY_LENGTH * 2

    def __init__(self, paths=None):
        self._log = util.get_logger('protocol')
        self._paths = {} if paths is None else paths

    @asyncio.coroutine
    def _new_connection(self, connection, path):
        # TODO: As context manager? _clean_path on disconnect
        """
        PathError
        Disconnected
        MessageError
        MessageFlowError
        """
        # Extract public key from path
        path = path.strip('/')

        # Validate path
        if len(path) != self.PATH_LENGTH:
            raise PathError(len(path))

        # Get path instance
        path = self._get_path(path)
        path.log.info('New connection')

        # Create client instance
        client = Client(connection)

        # Do handshake
        yield from self._do_handshake(client)

        # Keep alive and poll for messages
        raise NotImplementedError

    @asyncio.coroutine
    def _do_handshake(self, client):
        """
        Disconnected
        MessageError
        MessageFlowError
        """
        # Send server-hello
        my_cookie = os.urandom(16)
        message = ServerHelloMessage.create(client, my_cookie)
        yield from client.send(message)

        # Receive client-hello or client-auth
        message = yield from client.receive()
        if message.type == MessageType.client_hello:
            # Client is a responder
            client.type = ReceiverType.responder
        elif message.type == MessageType.client_auth:
            # Client is the initiator
            client.type = ReceiverType.initiator
        else:
            error = "Expected 'client-hello' or 'client-auth', got '{}'"
            raise MessageFlowError(error.format(message.type))

        # TODO: Continue here
        raise NotImplementedError

    def _get_path(self, path):
        if self._paths.get(path) is None:
            self._paths[path] = Path(path)
        return self._paths[path]

    def _check_receiver_type(self, message, receiver_type):
        # TODO: unused
        if message.receiver_type != receiver_type:
            raise MessageFlowError('Expected receiver type {}, got {}'.format(
                receiver_type, message.receiver_type))
