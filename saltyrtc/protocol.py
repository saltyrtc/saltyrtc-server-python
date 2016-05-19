import asyncio
import os

import websockets
import libnacl
import libnacl.public

from . import util
from .exception import *
from .common import (
    KEY_LENGTH,
    AddressType,
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
        """
        Return `True` in case the path is empty. A call to this property
        will also remove clients from the path whose connections are
        closed but have not been removed from the path. (However, in
        case that the path is not empty, this property does not ensure
        that all disconnected clients will be removed.)
        """
        for id_, client in self._slots.items():
            if client is not None:
                if client.connection_closed.done():
                    self.remove_client(id_)
                    self.log.warning('Removed dead client')
                else:
                    return False
        return True

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
        self.log.debug('Set initiator {}', initiator)
        # Update initiator's log name
        initiator.update_log_name(0x01)
        # Authenticated, assign id
        initiator.authenticated = True
        initiator.id = 0x01
        # Return previous initiator
        return previous_initiator

    def get_responder(self, id_):
        """
        Return a responder's :class:`PathClient` instance or `None`.

        Arguments:
            - `id_`: The identifier of the responder.

        Raises :exc:`ValueError` if `id_` is not a valid responder
        identifier.
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
        for id_, client in self._slots.items():
            if id_ > 0x01 and client is None:
                self._slots[id_] = responder
                self.log.debug('Added responder {}', responder)
                # Update responder's log name
                responder.update_log_name(id_)
                # Authenticated, set and return assigned slot id
                responder.authenticated = True
                responder.id = id_
                return id_
        raise SlotsFullError('No free slots on path')

    def remove_client(self, client):
        """
        Remove a client (initiator or responder) from the
        :class:`Path`.

        Arguments:
             - `client`: The :class:`PathClient` instance.
        """

        if not client.authenticated:
            # Client has not been authenticated. Nothing to do.
            return
        id_ = client.id
        assert 0x00 < id_ <= 0xff
        self._slots[id_] = None
        self.log.debug('Removed {}', 'initiator' if id_ == 0x01 else 'responder')


class PathClient:
    __slots__ = (
        '_log', '_connection', '_client_key', '_server_key',
        '_sequence_number_out', '_sequence_number_in', '_cookie_out', '_cookie_in',
        '_channel_fragment_out', '_channel_fragment_in',
        '_box', '_id', 'type', 'authenticated'
    )

    def __init__(self, connection, path_number, initiator_key, server_key=None):
        self._log = util.get_logger('path.{}.client'.format(path_number))
        self._connection = connection
        self._client_key = initiator_key
        self._server_key = server_key
        self._sequence_number_out = 0
        self._sequence_number_in = 0
        self._cookie_out = None
        self._cookie_in = None
        self._channel_fragment_out = None
        self._channel_fragment_in = None
        self._box = None
        self._id = 0x00
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
    def id(self):
        """
        Return the assigned id on the :class:`Path`.
        """
        return self._id

    @id.setter
    def id(self, id_):
        """
        Assign the id. Only :class:`Path` may set the id!
        """
        self._id = id_
        self._log.debug('Assigned id: {}', id_)

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

    @property
    def sequence_number_out(self):
        """
        Return the sequence number of the server (outgoing messages).
        """
        return self._sequence_number_out

    @property
    def sequence_number_in(self):
        """
        Return the sequence number of the client (incoming messages).
        """
        return self._sequence_number_in

    @property
    def cookie_out(self):
        """
        Return the cookie of the server (outgoing messages).
        """
        if self._cookie_out is None:
            self._cookie_out = os.urandom(16)
        return self._cookie_out

    @property
    def cookie_in(self):
        """
        Return the cookie of the client (incoming messages).
        """
        return self._cookie_in

    @property
    def channel_fragment_out(self):
        """
        Return the channel fragment of the server (outgoing messages).
        """
        if self._channel_fragment_out is None:
            self._channel_fragment_out = os.urandom(2)
        return self._channel_fragment_out

    @property
    def channel_fragment_in(self):
        """
        Return the channel fragment of the client (incoming messages).
        """
        return self._channel_fragment_in

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

    def valid_cookie(self, cookie_in):
        """
        Return `True` if the 16 byte cookie is the valid cookie of the
        client (or the cookie has not been set, yet).
        """
        if self.cookie_in is None:
            # Ensure that the client uses another cookie than we do
            if cookie_in == self.cookie_out:
                return False

            # First message: Set cookie
            self._cookie_in = cookie_in
            return True
        else:
            return cookie_in == self.cookie_in

    def valid_channel_fragment(self, channel_fragment_in):
        """
        Return `True` if the 2 byte channel fragment is the valid
        channel fragment of the client (or the channel fragment has not
        been set, yet).
        """
        if self.channel_fragment_in is None:
            self._channel_fragment_in = channel_fragment_in
            return True
        else:
            return channel_fragment_in == self.channel_fragment_in

    def p2p_allowed(self, destination_type):
        """
        Return `True` if :class:`RawMessage` instances are allowed and
        can be sent to the requested :class:`AddressType`.
        """
        return self.authenticated and self.type != destination_type

    @asyncio.coroutine
    def send(self, message):
        """
        Disconnected
        MessageFlowError
        """
        # Check source and destination type
        is_from_server = message.source_type == AddressType.server
        if not is_from_server and not self.p2p_allowed(message.destination_type):
            raise MessageFlowError('Currently not allowed to dispatch P2P messages')

        # Pack if not packed
        if isinstance(message, AbstractMessage):
            self._log.debug('Packing message')
            data = message.pack(self)
            self._log.trace('server >> {}', message)
        else:
            data = message

        # Send data
        self._log.debug('Sending message')
        self._sequence_number_out += 1
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
        data = unpack(self, data)
        self._sequence_number_in += 1
        self._log.debug('Unpacked message')
        self._log.trace('server << {}', data)
        return data

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
