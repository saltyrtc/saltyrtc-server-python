import asyncio
import os
import binascii

import websockets
import libnacl
import libnacl.public

from . import util
from .exception import *
from .common import KEY_LENGTH, COOKIE_LENGTH, ReceiverType, MessageType
from .message import (
    unpack,
    ServerHelloMessage, ServerAuthMessage,
    NewResponderMessage,
)


class Path:
    __slots__ = ('_slots', 'log', 'initiator_key', 'number')

    def __init__(self, initiator_key, number):
        self._slots = {id_: None for id_ in range(0x01, 0xff + 1)}
        self.log = util.get_logger('path.{}'.format(number))
        self.initiator_key = initiator_key
        self.number = number

    @property
    def empty(self):
        return all((client is None for client in self._slots.values()))

    def get_initiator(self):
        """Return the initiator's :class:`Client` instance or `None`."""
        return self._slots.get(0x01)

    def set_initiator(self, initiator):
        """
        Set the initiator's :class:`Client` instance.

        Arguments:
            - `initiator`: A :class:`Client` instance.

        Return the previously set initiator or `None`.
        """
        previous_initiator = self._slots.get(0x01)
        self._slots[0x01] = initiator
        # Update initiator's log name
        initiator.update_log_name(0x01)
        # Return previous initiator
        return previous_initiator

    def get_responder(self, id_):
        """
        Return a responder's :class:`Client` instance or `None`.

        Arguments:
            - `id_`: The receiver identifier of the responder.

        Raises :exc:`ValueError` if `id_` is not a valid responder
        receiver identifier.
        """
        if not 0x01 < id_ <= 0xff:
            raise ValueError('Invalid responder identifier')
        return self._slots.get(id_)

    def get_responder_ids(self):
        """
        Return a list of responder's identifiers (slots).
        """
        return [id_ for id_ in self._slots.keys() if id_ > 0x01]

    def add_responder(self, responder):
        """
        Set a responder's :class:`Client` instance.

        Arguments:
            - `client`: A :class:`Client` instance.

        Raises :exc:`SlotsFullError` if no free slot exists on the path.

        Return the assigned slot identifier.
        """
        for id_, client in self._slots:
            if client is None:
                self._slots[id_] = responder
                # Update responder's log name
                responder.update_log_name(id_)
                # Return assigned slot id
                return id_
        raise SlotsFullError('No free slots on path')


class Client:
    __slots__ = (
        '_log', '_connection', '_client_key', '_server_key', '_box',
        'type', 'authenticated'
    )

    def __init__(self, connection, path_number, initiator_key, server_key=None):
        self._log = util.get_logger('path.{}.client'.format(path_number))
        self._connection = connection
        self._client_key = initiator_key
        self._server_key = server_key
        self._box = None
        self.type = None
        self.authenticated = False

    @property
    def server_key(self):
        """
        Return the server's :class:`libnacl.public.SecretKey` instance.
        """
        if self._server_key is None:
            self._server_key = libnacl.public.SecretKey()
        return self._server_key

    @property
    def box(self):
        """
        Return the :class:`libnacl.public.Box` instance.
        """
        if self._box is None:
            self._box = libnacl.public.Box(self.server_key, self._client_key)
        return self._box

    def set_client_key(self, public_key):
        """
        Set the public key of the client and update the internal box.

        Arguments:
            - `public_key`: A :class:`libnacl.public.PublicKey`.
        """
        self._client_key = public_key
        self._box = libnacl.public.Box(self.server_key, public_key)
        self._log.debug('Client key updated')

    def update_log_name(self, slot_id):
        """
        Update the logger's name by the assigned slot identifier.

        Arguments:
            - `slot_id`: The slot identifier of the client.
        """
        self._log.name += '.{}'.format(slot_id)

    def p2p_allowed(self, receiver_type):
        """
        Return `True` if :class:`RawMessage` instances are allowed and
        can be sent to the requested :class:`ReceiverType`.
        """
        return self.authenticated and self.type != receiver_type

    @asyncio.coroutine
    def send(self, message):
        """
        Disconnected
        """
        # Pack message
        self._log.debug('Packing message')
        data = message.pack(self)

        # Send data
        self._log.debug('Sending message')
        try:
            yield from self._connection.send(data)
        except websockets.ConnectionClosed as exc:
            self._log.debug('Connection closed while sending')
            raise Disconnected() from exc

    @asyncio.coroutine
    def receive(self):
        """
        Disconnected
        """
        # Receive data
        self._log.debug('Waiting for message')
        try:
            data = yield from self._connection.recv()
        except websockets.ConnectionClosed as exc:
            self._log.debug('Connection closed while receiving')
            raise Disconnected() from exc
        self._log.debug('Received message')

        # Unpack data and return
        self._log.debug('Unpacking message')
        return unpack(self, data)


class Protocol:
    PATH_LENGTH = KEY_LENGTH * 2

    def __init__(self, paths=None, loop=None):
        self._path_number = 0
        self._log = util.get_logger('protocol')
        self._paths = {} if paths is None else paths
        self._loop = asyncio.get_event_loop() if loop is None else loop

    @asyncio.coroutine
    def _new_connection(self, connection, path):
        # TODO: As context manager? _clean_path on disconnect
        """
        PathError
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        """
        self._log.debug('New connection')

        # Extract public key from path
        initiator_key = path.strip('/')

        # Validate key
        if len(initiator_key) != self.PATH_LENGTH:
            raise PathError('Invalid path length: {}'.format(len(initiator_key)))
        try:
            initiator_key = binascii.unhexlify(initiator_key)
        except binascii.Error as exc:
            raise PathError('Could not unhexlify path') from exc

        # Get path instance
        path = self._get_path(initiator_key)
        path.log.debug('New connection')

        # Create client instance
        client = Client(connection, path.number, initiator_key)

        # Do handshake
        path.log.debug('Starting handshake')
        yield from self._handshake(path, client)
        path.log.debug('Handshake completed')

        # Keep alive and poll for messages
        raise NotImplementedError

    @asyncio.coroutine
    def _handshake(self, path, client):
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        """
        # Send server-hello
        server_cookie = os.urandom(COOKIE_LENGTH)
        message = ServerHelloMessage.create(client.server_key.pk, server_cookie)
        path.log.debug('Sending server-hello')
        yield from client.send(message)

        # Receive client-hello or client-auth
        path.log.debug('Waiting for client-hello')
        message = yield from client.receive()
        if message.type == MessageType.client_auth:
            path.log.debug('Received client-auth')
            # Client is the initiator
            client.type = ReceiverType.initiator
            yield from self._handshake_initiator(path, client, message, server_cookie)
        elif message.type == MessageType.client_hello:
            path.log.debug('Received client-hello')
            # Client is a responder
            client.type = ReceiverType.responder
            yield from self._handshake_responder(path, client, message, server_cookie)

        else:
            error = "Expected 'client-hello' or 'client-auth', got '{}'"
            raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def _handshake_initiator(self, path, initiator, message, server_cookie):
        """
        Disconnected
        MessageError
        MessageFlowError
        """
        # Validate cookie
        path.log.debug('Validating cookie')
        if not util.consteq(message.server_cookie, server_cookie):
            raise MessageError('Cookies do not match')

        # Authenticated
        initiator.authenticated = True
        previous_initiator = path.set_initiator(initiator)
        # Drop previous initiator (we don't care about any exceptions)
        path.log.debug('Dropping previous initiator: {}', previous_initiator)
        self._loop.create_task(previous_initiator.close())

        # Send server-auth
        client_cookie = message.client_cookie
        responder_ids = path.get_responder_ids()
        message = ServerAuthMessage.create(client_cookie, responder_ids=responder_ids)
        path.log.debug('Sending server-auth including responder ids')
        yield from initiator.send(message)

    @asyncio.coroutine
    def _handshake_responder(self, path, responder, message, server_cookie):
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        """
        # Set key on client
        responder.set_client_key(message.client_public_key)

        # Receive client-auth
        message = yield from responder.receive()
        if message.type != MessageType.client_auth:
            error = "Expected 'client-auth', got '{}'"
            raise MessageFlowError(error.format(message.type))

        # Validate cookie
        if not util.consteq(message.server_cookie, server_cookie):
            raise MessageError('Cookies do not match')

        # Authenticated
        responder.authenticated = True
        id_ = path.add_responder(responder)
        client_cookie = message.client_cookie

        # Send new-responder message if initiator is present
        initiator = path.get_initiator()
        if initiator is not None:
            message = NewResponderMessage.create(id_)
            path.log.debug('Sending new-responder to initiator')
            # TODO: Handle exceptions?
            self._loop.create_task(initiator.send(message))

        # Send server-auth
        message = ServerAuthMessage.create(client_cookie)
        path.log.debug('Sending server-auth without responder ids')
        yield from initiator.send(message)

    def _get_path(self, initiator_key):
        if self._paths.get(initiator_key) is None:
            self._path_number += 1
            self._paths[initiator_key] = Path(initiator_key, self._path_number)
            self._log.debug('Created new path: {}', self._path_number)
        return self._paths[initiator_key]

    def _clean_path(self, path):
        if path.empty:
            del self._paths[path.initiator_key]
            self._log.debug('Removed empty path: {}', path.number)
