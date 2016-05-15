import asyncio

import websockets
import libnacl
import libnacl.public

from . import util
from .exception import *
from .common import (
    KEY_LENGTH,
)
from .message import (
    unpack,
    AbstractMessage,
)

__all__ = (
    'Path',
    'PathClient',
    'Protocol',
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
        """
        Return the initiator's :class:`PathClient` instance or `None`.
        """
        return self._slots.get(0x01)

    def set_initiator(self, initiator):
        """
        Set the initiator's :class:`PathClient` instance.

        Arguments:
            - `initiator`: A :class:`PathClient` instance.

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
        Return a responder's :class:`PathClient` instance or `None`.

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
        return [id_ for id_, responder in self._slots.items()
                if id_ > 0x01 and responder is not None]

    def add_responder(self, responder):
        """
        Set a responder's :class:`PathClient` instance.

        Arguments:
            - `client`: A :class:`PathClient` instance.

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


class PathClient:
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
    def connection_closed(self):
        """
        Return the 'connection_closed' future of the underlying
        WebSocket connection.
        """
        return self._connection.connection_closed

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
        # Pack if not packed
        if isinstance(message, AbstractMessage):
            self._log.debug('Packing message')
            data = message.pack(self)
        else:
            data = message

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
        try:
            data = yield from self._connection.recv()
        except websockets.ConnectionClosed as exc:
            self._log.debug('Connection closed while receiving')
            raise Disconnected() from exc
        self._log.debug('Received message')

        # Unpack data and return
        self._log.debug('Unpacking message')
        return unpack(self, data)

    @asyncio.coroutine
    def ping(self):
        """
        Disconnected
        """
        self._log.debug('Sending ping')
        try:
            yield from self._connection.ping()
        except websockets.ConnectionClosed as exc:
            self._log.debug('Connection closed while pinging')
            raise Disconnected() from exc

    @asyncio.coroutine
    def close(self, code=1000):
        # Note: We are not sending a reason for security reasons.
        yield from self._connection.close(code=code)


class Protocol:
    PATH_LENGTH = KEY_LENGTH * 2
