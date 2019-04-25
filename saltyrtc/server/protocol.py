import asyncio
import os
import struct
# noinspection PyUnresolvedReferences
from typing import Dict  # noqa
from typing import (
    Any,
    Iterable,
    Optional,
    Type,
    TypeVar,
    Union,
    cast,
)

import libnacl
import libnacl.public
import websockets

from . import util
from .common import (
    COOKIE_LENGTH,
    INITIATOR_ADDRESS,
    KEEP_ALIVE_INTERVAL_DEFAULT,
    KEEP_ALIVE_INTERVAL_MIN,
    KEEP_ALIVE_TIMEOUT,
    SERVER_ADDRESS,
    Address,
    AddressType,
    ClientAddress,
    ClientState,
    CloseCode,
    OverflowSentinel,
    ResponderAddress,
)
from .exception import (
    Disconnected,
    InternalError,
    MessageError,
    MessageFlowError,
    SlotsFullError,
)
from .message import (
    IncomingMessageMixin,
    OutgoingMessageMixin,
    unpack,
)
from .task import (
    JobQueue,
    Tasks,
)
# noinspection PyUnresolvedReferences
from .typing import Result  # noqa
from .typing import (
    ClientCookie,
    ClientPublicKey,
    IncomingSequenceNumber,
    InitiatorPublicPermanentKey,
    MessageBox,
    OutgoingSequenceNumber,
    Packet,
    PingInterval,
    ResponderPublicSessionKey,
    SequenceNumber,
    ServerCookie,
    ServerSecretPermanentKey,
    ServerSecretSessionKey,
    SignBox,
)

__all__ = (
    'Path',
    'PathClient',
)

# Do not export!
SNT = TypeVar('SNT', bound=SequenceNumber)


class Path:
    __slots__ = (
        '_initiator',
        '_responders',
        'log',
        'initiator_key',
        'number',
        'attached'
    )

    def __init__(
            self,
            initiator_key: InitiatorPublicPermanentKey,
            number: int,
            attached: bool = True,
    ) -> None:
        self._initiator = None  # type: Optional[PathClient]
        self._responders = {}  # type: Dict[ResponderAddress, PathClient]
        self.log = util.get_logger('path.{}'.format(number))
        self.initiator_key = initiator_key
        self.number = number
        self.attached = attached

    @property
    def empty(self) -> bool:
        """
        Return whether the path is empty.
        """
        return self._initiator is None and len(self._responders) == 0

    def has_client(self, client: 'PathClient') -> bool:
        """
        Return whether a client's :class:`PathClient` instance is still
        available on the path.

        Arguments:
            - `client`: The :class:`PathClient` instance to look for.
        """
        # Note: No need to check for an unassigned ID since the server's ID will never
        #       be available in the slots.
        id_ = client.id

        # Check for initiator
        if id_ == INITIATOR_ADDRESS:
            return self._initiator == client

        # Check for responder
        try:
            id_ = ResponderAddress(id_)
        except ValueError:
            return False
        try:
            return self._responders[id_] == client
        except KeyError:
            return False

    def get_initiator(self) -> 'PathClient':
        """
        Return the initiator's :class:`PathClient` instance.

        Raises :exc:`KeyError` if there is no initiator.
        """
        if self._initiator is None:
            raise KeyError('No initiator present')
        return self._initiator

    def set_initiator(self, initiator: 'PathClient') -> Optional['PathClient']:
        """
        Set the initiator's :class:`PathClient` instance.

        Arguments:
            - `initiator`: A :class:`PathClient` instance.

        Raises :exc:`ValueError` in case of a state violation on the
        :class:`PathClient`.

        Return the previously set initiator or `None`.
        """
        previous_initiator = self._initiator
        self._initiator = initiator
        self.log.debug('Set initiator {}', initiator)

        # Update initiator's log name
        initiator.update_log_name(INITIATOR_ADDRESS)
        # Authenticated, assign id
        initiator.authenticate(INITIATOR_ADDRESS)
        # Return previous initiator
        return previous_initiator

    def get_responder(self, id_: ResponderAddress) -> 'PathClient':
        """
        Return a responder's :class:`PathClient` instance.

        Arguments:
            - `id_`: The identifier of the responder.

        Raises :exc:`KeyError`: If `id_` cannot be associated to a
        :class:`PathClient` instance.
        """
        return self._responders[id_]

    def get_responder_ids(self) -> Iterable[ResponderAddress]:
        """
        Return an iterable of responder identifiers (slots).
        """
        return self._responders.keys()

    def add_responder(self, responder: 'PathClient') -> ResponderAddress:
        """
        Set a responder's :class:`PathClient` instance.

        Arguments:
            - `responder`: A :class:`PathClient` instance.

        Raises:
            - :exc:`SlotsFullError` if no free slot exists on the path.
            - :exc:`ValueError` in case of a state violation on the
              :class:`PathClient`.

        Return the assigned slot identifier.
        """
        # Calculate slot id
        id_ = len(self._responders) + 0x02
        try:
            id_ = ResponderAddress(id_)
        except ValueError as exc:
            raise SlotsFullError('No free slot on path') from exc

        # Set responder
        self._responders[id_] = responder
        self.log.debug('Added responder {}', responder)
        # Update responder's log name
        responder.update_log_name(id_)
        # Authenticated, set and return assigned slot id
        responder.authenticate(id_)
        return id_

    def remove_client(self, client: 'PathClient') -> None:
        """
        Remove a client (initiator or responder) from the
        :class:`Path`.

        .. important:: Shall only be called from the client's
           own :class:`Protocol` instance or from another client's
           :class.`Protocol` instance in case it is dropping a client.

        Arguments:
             - `client`: The :class:`PathClient` instance.

        Raises :exc:`KeyError` in case the client provided an
        invalid slot identifier.
        """
        if client.state == ClientState.restricted:
            # Client has never been authenticated. Nothing to do.
            return

        # Remove initiator or responder
        id_ = client.id
        is_initiator = id_ == INITIATOR_ADDRESS
        if is_initiator:
            if self.get_initiator() != client:
                # Note: This is absolutely fine and happens when another initiator
                #       takes the place of a previous initiator.
                return
            self._initiator = None
        else:
            try:
                id_ = ResponderAddress(id_)
            except ValueError:
                raise KeyError('Invalid responder id: {}'.format(id_))
            del self._responders[id_]
        self.log.debug('Removed {}', 'initiator' if is_initiator else 'responder')


class PathClient:
    __slots__ = (
        '_loop',
        '_state',
        '_connection',
        '_connection_closed_future',
        '_client_key',
        '_server_permanent_key',
        '_server_session_key',
        '_sequence_number_out',
        '_sequence_number_in',
        '_cookie_out',
        '_cookie_in',
        '_csn_out',
        '_csn_in',
        '_box',
        '_sign_box',
        '_id',
        '_keep_alive_interval',
        'log',
        'type',
        'keep_alive_timeout',
        'keep_alive_pings',
        'jobs',
        'tasks',
    )

    @staticmethod
    def _increment_csn(
            csn: Union[SNT, Type[OverflowSentinel]],
    ) -> Union[SNT, Type[OverflowSentinel]]:
        """
        Increment a combined sequence number.

        Return OverflowSentinel in case the number would overflow a
        48-bit unsigned integer, otherwise the passed sequence number.
        """
        if csn is OverflowSentinel:
            return OverflowSentinel
        csn_value = cast('int', csn)
        csn_value += 1
        if csn_value & 0xf000000000000 != 0:
            return OverflowSentinel
        else:
            return cast('SNT', csn_value)

    def __init__(
            self,
            connection: websockets.WebSocketServerProtocol,
            path_number: int,
            initiator_key: InitiatorPublicPermanentKey,
            loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._loop = asyncio.get_event_loop() if loop is None else loop
        self._state = ClientState.restricted
        self._connection = connection  # type: websockets.WebSocketServerProtocol
        connection_closed_future = \
            asyncio.Future(loop=self._loop)  # type: asyncio.Future[Disconnected]
        self._connection_closed_future = connection_closed_future
        self._client_key = initiator_key  # type: ClientPublicKey
        self._server_permanent_key = None  # type: Optional[ServerSecretPermanentKey]
        self._server_session_key = None  # type: Optional[ServerSecretSessionKey]
        self._cookie_out = None  # type: Optional[ServerCookie]
        self._cookie_in = None  # type: Optional[ClientCookie]
        self._csn_out = \
            None  # type: Optional[Union[OutgoingSequenceNumber, Type[OverflowSentinel]]]
        self._csn_in = \
            None  # type: Optional[Union[IncomingSequenceNumber, Type[OverflowSentinel]]]
        self._box = None  # type: Optional[MessageBox]
        self._sign_box = None  # type: Optional[SignBox]
        self._id = SERVER_ADDRESS  # type: Address
        self._keep_alive_interval = KEEP_ALIVE_INTERVAL_DEFAULT
        self.log = util.get_logger('path.{}.client.{:x}'.format(path_number, id(self)))
        self.type = None  # type: Optional[AddressType]
        self.keep_alive_timeout = KEEP_ALIVE_TIMEOUT
        self.keep_alive_pings = 0
        self.jobs = JobQueue(self.log, self._loop)  # type: JobQueue
        self.tasks = Tasks(self.log, self._loop)

        # Schedule connection closed future
        def _connection_closed(_: Any) -> None:
            connection_closed_future.set_result(Disconnected(connection.close_code))
        self._connection.connection_lost_waiter.add_done_callback(_connection_closed)

    def __str__(self) -> str:
        type_ = 'undetermined' if self.type is None else str(self.type)
        return 'PathClient(role={}, id={}, at={})'.format(
            type_, self._id, hex(id(self)))

    @property
    def state(self) -> ClientState:
        """
        Return the current :class:`ClientState` of the client.
        """
        return self._state

    @state.setter
    def state(self, state: ClientState) -> None:
        """
        Update the :class:`ClientState` of the client.

        Raises :exc:`ValueError` in case the state is not following
        the strict state order as defined by :class`ClientState`.
        """
        if state != self._state.next:
            raise ValueError('State {} cannot be updated to {}'.format(
                self._state, state))
        self.log.debug('State {} -> {}', self._state.name, state.name)
        self._state = state

    @property
    def connection_closed_future(self) -> 'asyncio.Future[Disconnected]':
        """
        Resolves once the connection has been closed.

        Return the close code.
        """
        return asyncio.shield(self._connection_closed_future, loop=self._loop)

    @property
    def id(self) -> Address:
        """
        Return the assigned id on the :class:`Path`.
        """
        return self._id

    @property
    def keep_alive_interval(self) -> PingInterval:
        """
        Return the currently set keep alive interval.
        """
        return self._keep_alive_interval

    @keep_alive_interval.setter
    def keep_alive_interval(self, interval: PingInterval) -> None:
        """
        Assign a new keep alive interval. Will ignore values less than
        `KEEP_ALIVE_INTERVAL_MIN`.
        """
        if interval >= KEEP_ALIVE_INTERVAL_MIN:
            self._keep_alive_interval = interval

    @property
    def client_key(self) -> ClientPublicKey:
        """
        Return the client's permanent or session key as :class:`bytes`.

        .. warning:: This is the initiator's key at default if no other
                     client key has been set!
        """
        return self._client_key

    @property
    def server_key(self) -> ServerSecretSessionKey:
        """
        Return the server's session :class:`libnacl.public.SecretKey`
        instance.
        """
        if self._server_session_key is None:
            self._server_session_key = ServerSecretSessionKey(libnacl.public.SecretKey())
        return self._server_session_key

    @property
    def server_permanent_key(self) -> ServerSecretPermanentKey:
        """
        Return the server's permanent :class:`libnacl.public.SecretKey`
        instance chosen by the client.

        Raises `InternalError` in case the key has not been set, yet.
        """
        if self._server_permanent_key is None:
            raise InternalError("Server's permanent secret key instance not set")
        return self._server_permanent_key

    @server_permanent_key.setter
    def server_permanent_key(self, key: ServerSecretPermanentKey) -> None:
        """
        Set the server's permanent :class:`libnacl.public.SecretKey`
        instance chosen by the client.
        """
        self._server_permanent_key = key

    @property
    def box(self) -> MessageBox:
        """
        Return the session's :class:`libnacl.public.Box` instance.
        """
        if self._box is None:
            self._box = MessageBox(libnacl.public.Box(self.server_key, self._client_key))
        return self._box

    @property
    def sign_box(self) -> SignBox:
        """
        Return the :class:`libnacl.public.Box` instance that is used for
        signing the keys in the 'server-auth' message.

        Raises `InternalError` in case the server's permanent key has
        not been set, yet.
        """
        if self._sign_box is None:
            self._sign_box = SignBox(libnacl.public.Box(
                self.server_permanent_key, self._client_key))
        return self._sign_box

    @property
    def cookie_out(self) -> ServerCookie:
        """
        Return the cookie of the server (outgoing messages).
        """
        if self._cookie_out is None:
            self._cookie_out = ServerCookie(os.urandom(COOKIE_LENGTH))
        return self._cookie_out

    @property
    def cookie_in(self) -> ClientCookie:
        """
        Return the cookie of the client (incoming messages).

        Raises `InternalError` in case the client's cookie has not been
        set, yet.
        """
        if self._cookie_in is None:
            raise InternalError("Client's cookie not set!")
        return self._cookie_in

    @property
    def csn_out(self) -> Union[OutgoingSequenceNumber, Type[OverflowSentinel]]:
        """
        Return the pending combined sequence number of the server
        (outgoing messages).
        """
        if self._csn_out is None:
            # Initialise the trailing 32 bits of the uint48 number with random bits
            initial_number, *_ = struct.unpack('!Q', b'\x00' * 4 + os.urandom(4))
            self._csn_out = OutgoingSequenceNumber(initial_number)
        return self._csn_out

    @property
    def csn_in(self) -> Union[IncomingSequenceNumber, Type[OverflowSentinel]]:
        """
        Return the pending combined sequence number of the client
        (incoming messages).

        Raises `InternalError` in case the client's combined sequence
        number has not been set, yet.
        """
        if self._csn_in is None:
            raise InternalError("Client's combined sequence number not set!")
        return self._csn_in

    def increment_csn_out(self) -> None:
        """
        Increment the combined sequence number of the server (outgoing
        messages). Will set the number to OverflowSentinel in case
        the number would overflow a 48-bit unsigned integer.
        """
        csn = self._increment_csn(self.csn_out)
        self._csn_out = csn

    def increment_csn_in(self) -> None:
        """
        Update the combined sequence number of the client (incoming
        messages). Will set the number to OverflowSentinel in case
        the number would overflow a 48-bit unsigned integer.

        Raises `InternalError` in case the client's combined sequence
        number has not been set, yet.
        """
        csn = self._increment_csn(self.csn_in)
        self._csn_in = csn

    def set_client_key(self, public_key: ResponderPublicSessionKey) -> None:
        """
        Set the public key of the client and update the internal box.

        Arguments:
            - `public_key`: A :class:`libnacl.public.PublicKey`.
        """
        self._client_key = public_key
        self._box = MessageBox(libnacl.public.Box(self.server_key, public_key))
        self.log.debug('Client key updated')

    def authenticate(self, id_: ClientAddress) -> None:
        """
        Authenticate the client and assign it an id.

        .. important:: Only :class:`Path` may call this!

        Raises :exc:`ValueError` in case the previous state was not
        :attr:`ClientState.restricted`.
        """
        # noinspection PyAttributeOutsideInit
        self.state = ClientState.authenticated
        self._id = id_
        self.log.debug('Assigned id: {}', id_)

    def update_log_name(self, slot_id: ClientAddress) -> None:
        """
        Update the logger's name by the assigned slot identifier.

        Arguments:
            - `slot_id`: The slot identifier of the client.
        """
        self.log.name += '.0x{:02x}'.format(slot_id)

    def valid_cookie(self, cookie_in: Optional[ClientCookie]) -> bool:
        """
        Return `True` if the 16 byte cookie is the valid cookie of the
        client (or the cookie has not been set, yet).
        """
        if self._cookie_in is None:
            # Ensure that the client uses another cookie than we do
            if cookie_in == self.cookie_out:
                self.log.notice('Server and client cookies are the same')
                return False

            # First message: Set cookie
            self._cookie_in = cookie_in
            return True
        else:
            if cookie_in != self.cookie_in:
                self.log.notice('Client sent wrong cookie')
                return False
            return True

    def validate_csn_in(self, csn_in: IncomingSequenceNumber) -> None:
        """
        Validate the combined sequence number for incoming messages
        from the client.

        Raises:
            - :exc:`MessageError` in case this is the first message
              from the client and the leading 16 bits of the combined
              sequence number are not `0`.
            - :exc:`MessageError` in case the 6 byte combined sequence
              number is not the expected sequence number of the client.
            - :exc:`MessageFlowError` in case no messages can be
              received from the client as the combined sequence number
              has reset to `0`.
        """
        if self._csn_in is None:
            # Ensure that the leading 16 bits are 0
            if csn_in & 0xffff00000000 != 0:
                raise MessageError('Invalid sequence number, leading 16 bits are not 0')

            # First message: Set combined sequence number
            self._csn_in = csn_in

        # Ensure that the incoming CSN counter did not overflow
        if self._csn_in is OverflowSentinel:
            raise MessageFlowError(('Cannot receive any more messages, due to a '
                                    'sequence number counter overflow'))

        # Check that the CSN matches the expected CSN
        if csn_in != self._csn_in:
            raise MessageError('Invalid sequence number, expected {}, got {}'.format(
                self._csn_in, csn_in
            ))

    def p2p_allowed(self, destination_type: AddressType) -> bool:
        """
        Return `True` if :class:`RelayMessage` instances are allowed
        and can be sent to the requested :class:`AddressType`.
        """
        return self.state == ClientState.authenticated and self.type != destination_type

    async def send(self, message: OutgoingMessageMixin) -> None:
        """
        Disconnected
        MessageError
        MessageFlowError
        """
        # Pack
        self.log.debug('Packing message: {}', message.type)
        data = message.pack(self)
        self.log.trace('server >> {}', message)

        # Send data
        self.log.debug('Sending message')
        try:
            await self._connection.send(data)
        except websockets.ConnectionClosed as exc:
            self.log.debug('Connection closed while sending')
            disconnected = Disconnected(exc.code)
            self.jobs.close(Result(disconnected))
            raise disconnected from exc

    async def receive(self) -> IncomingMessageMixin:
        """
        Disconnected
        """
        # Safeguard
        # Note: This should never happen since the receive queue will
        #       be stopped when a client is being dropped.
        assert self.state < ClientState.dropped

        # Receive data
        try:
            data = await self._connection.recv()
        except websockets.ConnectionClosed as exc:
            self.log.debug('Connection closed while receiving')
            disconnected = Disconnected(exc.code)
            self.jobs.close(Result(disconnected))
            raise disconnected from exc
        self.log.debug('Received message')

        # Ensure binary
        if not isinstance(data, bytes):
            raise MessageError("Data must be 'bytes', not '{}'".format(type(data)))

        # Unpack data and return
        message = unpack(self, Packet(data))
        self.log.debug('Unpacked message: {}', message.type)
        self.log.trace('server << {}', message)
        return message

    async def ping(self) -> 'asyncio.Future[None]':
        """
        Disconnected
        """
        self.log.debug('Sending ping')
        try:
            pong_future = await self._connection.ping()
        except websockets.ConnectionClosed as exc:
            self.log.debug('Connection closed while pinging')
            disconnected = Disconnected(exc.code)
            self.jobs.close(Result(disconnected))
            raise disconnected from exc
        return cast('asyncio.Future[None]', pong_future)

    async def wait_pong(self, pong_future: 'asyncio.Future[None]') -> None:
        """
        Disconnected
        """
        self.log.debug('Waiting for pong')
        try:
            await pong_future
        except websockets.ConnectionClosed as exc:
            self.log.debug('Connection closed while waiting for pong')
            disconnected = Disconnected(exc.code)
            self.jobs.close(Result(disconnected))
            raise disconnected from exc

    async def close(self, code: int = 1000) -> None:
        """
        Initiate the closing procedure and wait for the connection to
        become closed.

        Arguments:
            - `close`: The close code.
        """
        # Close the job queue to ensure no further jobs can be
        # enqueued while the client is in the closing process.
        self.jobs.close(Result(Disconnected(code)))

        # Note: We are not sending a reason for security reasons.
        await self._connection.close(code=code)

    def drop(self, code: CloseCode) -> None:
        """
        Drop this client. Will enqueue the closing procedure and cancel
        all tasks of the client.

        .. important:: This should only be called by clients dropping
                       another client or when the server is closing.

        Arguments:
            - `close`: The close code.
        """
        # Schedule the closing procedure.
        # Note: The closing procedure would interrupt further send operations, thus we
        #       MUST enqueue it as a coroutine and NOT wrap in a Future. That way, it
        #       will not initiate the closing procedure before this client has executed
        #       all other pending jobs.
        self.log.debug('Scheduling delayed closing procedure', code)
        close_coroutine = self.close(code=code.value)

        # Close the job queue to ensure no further jobs can be
        # enqueued while the client is in the closing process.
        self.jobs.close(Result(Disconnected(code)), close_coroutine)

        # Cancel all tasks of the client.
        # Note: This will ensure that all messages forwarded towards the client to be
        #       dropped will still be forwarded as the job queue runner will continue
        #       processing jobs. But the client to be dropped will not be able to send
        #       any more messages towards the server or relay messages towards other
        #       clients.
        self.log.debug('Cancelling all running tasks')
        self.tasks.cancel(cast('asyncio.Future[Result]', self._connection_closed_future))

        # Mark as dropped (if authenticated)
        if self.state == ClientState.authenticated:
            self.state = ClientState.dropped
        self.log.debug('Client dropped, close code: {}', code)
