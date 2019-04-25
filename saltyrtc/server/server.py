import asyncio
import binascii
import functools
import ssl
from collections import OrderedDict
from typing import Awaitable  # noqa
from typing import ClassVar  # noqa
from typing import Dict  # noqa
from typing import List  # noqa
from typing import Set  # noqa
from typing import (
    Any,
    Coroutine,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

import websockets

from . import util
from .common import (
    COOKIE_LENGTH,
    INITIATOR_ADDRESS,
    KEY_LENGTH,
    NONCE_LENGTH,
    RELAY_TIMEOUT,
    AddressType,
    ClientAddress,
    ClientState,
    CloseCode,
    ResponderAddress,
    SubProtocol,
)
from .events import (
    Event,
    EventRegistry,
)
from .exception import (
    Disconnected,
    DowngradeError,
    InternalError,
    MessageError,
    MessageFlowError,
    PathError,
    PingTimeoutError,
    ServerKeyError,
    SignalingError,
    SlotsFullError,
)
from .message import (
    ClientAuthMessage,
    ClientHelloMessage,
    DisconnectedMessage,
    DropResponderMessage,
    NewInitiatorMessage,
    NewResponderMessage,
    RelayMessage,
    SendErrorMessage,
    ServerAuthMessage,
    ServerHelloMessage,
)
from .protocol import (
    Path,
    PathClient,
)
from .typing import (
    ChosenSubProtocol,
    DisconnectedData,
    EventCallback,
    EventData,
    InitiatorPublicPermanentKey,
    ListOrTuple,
    MessageId,
    NoReturn,
    PathHex,
    ResponderPublicSessionKey,
    Result,
    ServerCookie,
    ServerPublicPermanentKey,
    ServerSecretPermanentKey,
)

__all__ = (
    'serve',
    'ServerProtocol',
    'Paths',
    'Server',
)

# Constants
_JOB_QUEUE_JOIN_TIMEOUT = 10.0

# Do not export!
ST = TypeVar('ST', bound='Server')
CloseFuture = Union['asyncio.Future[None]', Coroutine[Any, Any, None]]
Keys = Mapping[ServerPublicPermanentKey, ServerSecretPermanentKey]


async def serve(
        ssl_context: Optional[ssl.SSLContext],
        keys: Optional[Sequence[ServerSecretPermanentKey]],
        paths: Optional['Paths'] = None,
        host: Optional[str] = None,
        port: int = 8765,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        event_callbacks: Optional[Mapping[Event, Iterable[EventCallback]]] = None,
        server_class: Optional[Type[ST]] = None,
        ws_kwargs: Optional[Mapping[str, Any]] = None,
) -> ST:
    """
    Start serving SaltyRTC Signalling Clients.

    Arguments:
        - `ssl_context`: An `ssl.SSLContext` instance for WSS.
        - `keys`: A sorted sequence of :class:`libnacl.public.SecretKey`
          instances containing permanent private keys of the server.
          The first key will be designated as the primary key.
        - `paths`: A :class:`Paths` instance that maps path names to
          :class:`Path` instances. Can be used to share paths on
          multiple WebSockets. Defaults to an empty paths instance.
        - `host`: The hostname or IP address the server will listen on.
          Defaults to all interfaces.
        - `port`: The port the client should connect to. Defaults to
          `8765`.
        - `loop`: A :class:`asyncio.BaseEventLoop` instance or `None`
          if the default event loop should be used.
        - `event_callbacks`: An optional dict with keys being an
          :class:`Event` and the value being a list of callback
          coroutines. The callback will be called every time the event
          occurs.
        - `server_class`: An optional :class:`Server` class to create
          an instance from.
        - `ws_kwargs`: Additional keyword arguments passed to
          :func:`websockets.server.serve`. Note that the fields `ssl`,
          `host`, `port`, `loop`, `subprotocols` and `ping_interval`
          will be overridden.

          If the `compression` field is not explicitly set,
          compression will be disabled (since the data to be compressed
          is already encrypted, compression will have little to no
          positive effect).

    Raises :exc:`ServerKeyError` in case one or more keys have been repeated.
    """
    if loop is None:
        loop = asyncio.get_event_loop()

    # Create paths if not given
    if paths is None:
        paths = Paths()

    # Create server
    if server_class is None:
        server_class = cast('Type[ST]', Server)
    server = server_class(keys, paths, loop=loop)

    # Register event callbacks
    if event_callbacks is not None:
        for event, callbacks in event_callbacks.items():
            for callback in callbacks:
                server.register_event_callback(event, callback)

    # Prepare arguments for the WS server
    if ws_kwargs is None:
        ws_kwargs = {}
    else:
        ws_kwargs = dict(ws_kwargs)
    ws_kwargs['ssl'] = ssl_context
    ws_kwargs['host'] = host
    ws_kwargs['port'] = port
    ws_kwargs.setdefault('compression', None)
    ws_kwargs['ping_interval'] = None  # Disable the keep-alive of the transport library
    ws_kwargs['subprotocols'] = server.subprotocols

    # Start WS server
    ws_server = await websockets.serve(server.handler, **ws_kwargs)

    # Set WS server instance
    server.server = ws_server

    # Return server
    return server


class ServerProtocol:
    PATH_LENGTH = KEY_LENGTH * 2  # type: ClassVar[int]

    __slots__ = (
        '_log',
        '_loop',
        '_server',
        'subprotocol',
        'path',
        'client',
        'handler_task'
    )

    def __init__(
            self,
            server: 'Server',
            subprotocol: SubProtocol,
            connection: websockets.WebSocketServerProtocol,
            ws_path: str,
            loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._log = util.get_logger('server.protocol')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # Server instance and subprotocol
        self._server = server
        self.subprotocol = subprotocol

        # Path and client instance
        self.path = None  # type: Optional[Path]
        self.client = None  # type: Optional[PathClient]
        self._log.debug('New connection on WS path {}', ws_path)

        # Get path and client instance as early as possible
        try:
            path, client = self.get_path_client(connection, ws_path)
        except PathError as exc:
            self._log.notice('Closing due to path error: {}', exc)

            async def close_with_protocol_error() -> None:
                await connection.close(code=CloseCode.protocol_error.value)
                self._server.notify_disconnected(
                    None, DisconnectedData(CloseCode.protocol_error.value))
            handler_coroutine = close_with_protocol_error()
        else:
            handler_coroutine = self.handler()
            client.log.info('Connection established')
            client.log.debug('Worker started')

            # Store path and client
            self.path = path
            self.client = client
            self._server.register(self)

        # Start handler task
        log_handler = functools.partial(
            self._log.exception, 'Unhandled exception in protocol handler:')
        # noinspection PyTypeChecker
        self.handler_task = self._loop.create_task(
            util.log_exception(handler_coroutine, log_handler))

    async def handler(self) -> None:
        client, path = self.client, self.path
        assert client is not None
        assert path is not None

        # Handle client until disconnected or an exception occurred
        hex_path = PathHex(binascii.hexlify(path.initiator_key).decode('ascii'))
        close_future = asyncio.Future(loop=self._loop)  # type: asyncio.Future[None]
        try:
            await self.handle_client()
        except Disconnected as exc:
            client.log.info('Connection closed (code: {})', exc.reason)
            close_future.set_result(None)
            close_awaitable = close_future  # type: Awaitable[None]
            self._server.notify_disconnected(hex_path, DisconnectedData(exc.reason))
        except PingTimeoutError:
            client.log.info('Closing because of a ping timeout')
            close_awaitable = client.close(CloseCode.timeout.value)
            self._server.notify_disconnected(
                hex_path, DisconnectedData(CloseCode.timeout.value))
        except SlotsFullError as exc:
            client.log.notice('Closing because all path slots are full: {}', exc)
            close_awaitable = client.close(code=CloseCode.path_full_error.value)
            self._server.notify_disconnected(
                hex_path, DisconnectedData(CloseCode.path_full_error.value))
        except ServerKeyError as exc:
            client.log.notice('Closing due to server key error: {}', exc)
            close_awaitable = client.close(code=CloseCode.invalid_key.value)
            self._server.notify_disconnected(
                hex_path, DisconnectedData(CloseCode.invalid_key.value))
        except InternalError as exc:
            client.log.exception('Closing due to an internal error:', exc)
            close_awaitable = client.close(code=CloseCode.internal_error.value)
            self._server.notify_disconnected(
                hex_path, DisconnectedData(CloseCode.internal_error.value))
        except SignalingError as exc:
            client.log.notice('Closing due to protocol error: {}', exc)
            close_awaitable = client.close(code=CloseCode.protocol_error.value)
            self._server.notify_disconnected(
                hex_path, DisconnectedData(CloseCode.protocol_error.value))
        except Exception as exc:
            client.log.exception('Closing due to exception:', exc)
            close_awaitable = client.close(code=CloseCode.internal_error.value)
            self._server.notify_disconnected(
                hex_path, DisconnectedData(CloseCode.internal_error.value))
        else:
            # Note: This should not ever happen since 'handle_client'
            #       contains an infinite loop that only stops due to an exception.
            client.log.error('Client closed without exception')
            close_future.set_result(None)
            close_awaitable = close_future

        # Schedule closing of the client
        # Note: This ensures the client is closed soon even if the job queue is holding
        #       us up.
        if not isinstance(close_awaitable, asyncio.Future):
            log_handler = functools.partial(
                self._log.exception, 'Unhandled exception in closing procedure:')
            # noinspection PyTypeChecker
            close_awaitable = self._loop.create_task(
                util.log_exception(close_awaitable, log_handler))

        # Wait until all queued jobs have been processed and the job queue runner
        # returned.
        #
        # Note: This ensure that a send-error message (and potentially other messages)
        #       are enqueued towards other clients before the disconnect message.
        try:
            await asyncio.wait_for(
                client.jobs.join(), _JOB_QUEUE_JOIN_TIMEOUT, loop=self._loop)
        except asyncio.TimeoutError:
            client.log.error(
                'Job queue did not complete within {} seconds', _JOB_QUEUE_JOIN_TIMEOUT)
        else:
            client.log.debug('Job queue completed')

        # Send disconnected message if client was authenticated
        if client.state == ClientState.authenticated:
            # Initiator: Send to all responders
            if client.type == AddressType.initiator:
                responder_ids = path.get_responder_ids()
                coroutines = []  # type: List[Coroutine[Any, Any, None]]
                for responder_id in responder_ids:
                    responder = path.get_responder(responder_id)

                    # Create message and add send coroutine to job queue of the responder
                    message = DisconnectedMessage.create(
                        responder_id, INITIATOR_ADDRESS)
                    responder.log.debug('Enqueueing disconnected message')
                    coroutines.append(responder.jobs.enqueue(responder.send(message)))
                try:
                    await asyncio.gather(*coroutines, loop=self._loop)
                except Exception as exc:
                    description = 'Error while dispatching disconnected messages to ' \
                                  'responders:'
                    client.log.exception(description, exc)
            # Responder: Send to initiator (if present)
            elif client.type == AddressType.responder:
                try:
                    initiator = path.get_initiator()
                except KeyError:
                    pass  # No initiator present
                else:
                    # Create message and add send coroutine to job queue of the
                    # initiator
                    message = DisconnectedMessage.create(
                        INITIATOR_ADDRESS, ResponderAddress(client.id))
                    initiator.log.debug('Enqueueing disconnected message')
                    try:
                        await initiator.jobs.enqueue(initiator.send(message))
                    except Exception as exc:
                        description = 'Error while dispatching disconnected message' \
                                      'to initiator:'
                        client.log.exception(description, exc)
            else:
                client.log.error('Invalid address type: {}', client.type)
        else:
            client.log.debug(
                'Skipping potential disconnected message due to {} state',
                client.state.name)

        # Wait for the connection to be closed
        await close_awaitable
        client.log.debug('WS connection closed')

        # Remove protocol from server and stop
        self._server.unregister(self)
        client.log.debug('Worker stopped')

    def close(self, code: CloseCode) -> None:
        """
        Close the underlying connection and stop the protocol.

        Arguments:
            - `code`: The close code.
        """
        # Note: The client will be set as early as possible without any yielding.
        #       Thus, self.client is either set and can be closed or the connection
        #       is already closing (see the constructor and 'get_path_client')
        if self.client is not None:
            # We need to use 'drop' in order to prevent the server from sending a
            # 'disconnect' message for each client.
            try:
                self._drop_client(self.client, code)
            except KeyError:
                # We can safely ignore this since clients will be removed immediately
                # from the path in case they are being dropped by another client.
                pass

    def get_path_client(
            self,
            connection: websockets.WebSocketServerProtocol,
            ws_path: str,
    ) -> Tuple[Path, PathClient]:
        # Extract public key from path
        initiator_key_hex = ws_path[1:]

        # Validate key
        if len(initiator_key_hex) != self.PATH_LENGTH:
            raise PathError('Invalid path length: {}'.format(len(initiator_key_hex)))
        try:
            initiator_key = InitiatorPublicPermanentKey(
                binascii.unhexlify(initiator_key_hex))
        except (binascii.Error, ValueError) as exc:
            raise PathError('Could not unhexlify path') from exc

        # Get path instance
        path = self._server.paths.get(initiator_key)

        # Create client instance
        client = PathClient(connection, path.number, initiator_key, loop=self._loop)

        # Return path and client
        return path, client

    async def handle_client(self) -> None:
        """
        SignalingError
        PathError
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        DowngradeError
        ServerKeyError
        InternalError
        """
        path, client = self.path, self.client
        assert path is not None
        assert client is not None
        tasks = set()  # type: Set[Coroutine[Any, Any, None]]

        # Do handshake
        client.log.debug('Starting handshake')
        try:
            await self.handshake()
        except Exception as exc:
            client.log.info('Handshake aborted')

            # Encountered an exception during the handshake.
            # Note: We already know the result (the exception), so we can cancel both
            #       job queue and tasks.
            result = Result(exc)
            client.jobs.cancel(result)
            client.tasks.cancel(result)
        else:
            # Check if the client is still connected to the path or has already been
            # dropped.
            #
            # Note: This can happen when the client is being picked up and dropped by
            #       another client while running the handshake. To prevent other race
            #       conditions, we have to add the client instance to the path early
            #       during the handshake.
            is_connected = path.has_client(client)
            if is_connected:
                client.log.info('Handshake completed')
            else:
                client.log.info('Handshake completed but client already dropped')

            # Task: Poll for messages
            hex_path = PathHex(binascii.hexlify(path.initiator_key).decode('ascii'))
            if client.type == AddressType.initiator:
                self._server.notify_initiator_connected(hex_path)
                if is_connected:
                    client.log.debug('Starting runner for initiator')
                    tasks.add(self.initiator_receive_loop())
            elif client.type == AddressType.responder:
                self._server.notify_responder_connected(hex_path)
                if is_connected:
                    client.log.debug('Starting runner for responder')
                    tasks.add(self.responder_receive_loop())
            else:
                raise ValueError('Invalid address type: {}'.format(client.type))

            # Task: Keep alive
            if is_connected:
                client.log.debug('Starting keep-alive task')
                tasks.add(self.keep_alive_loop())

        # Start the tasks and the job queue runner
        client.jobs.start(client.tasks.cancel)
        client.tasks.start(tasks)

        # Wait until complete
        # Note: This method ensures us that all tasks have been cancelled
        #       when it returns.
        result = await client.tasks.await_result()

        # Cancel pending jobs and remove client from path
        # Note: Removing the client needs to be done here since the re-raise hands
        #       the task back into the event loop allowing other tasks to get the
        #       client's path instance from the path while it is already effectively
        #       disconnected.
        client.jobs.cancel(result)
        try:
            path.remove_client(client)
        except KeyError:
            # We can safely ignore this since clients will be removed immediately
            # from the path in case they are being dropped by another client.
            pass
        self._server.paths.clean(path)

        # Done! Raise the result
        raise result

    async def handshake(self) -> None:
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        DowngradeError
        ServerKeyError
        """
        client = self.client
        assert client is not None

        # Send server-hello
        server_hello = ServerHelloMessage.create(
            ServerPublicPermanentKey(client.server_key.pk))
        client.log.debug('Sending server-hello')
        await client.send(server_hello)

        # Receive client-hello or client-auth
        client.log.debug('Waiting for client-hello or client-auth')
        client_auth = await client.receive()
        if isinstance(client_auth, ClientAuthMessage):
            client.log.debug('Received client-auth')
            # Client is the initiator
            client.type = AddressType.initiator
            await self.handshake_initiator(client_auth)
        elif isinstance(client_auth, ClientHelloMessage):
            client.log.debug('Received client-hello')
            # Client is a responder
            client.type = AddressType.responder
            await self.handshake_responder(client_auth)
        else:
            error = "Expected 'client-hello' or 'client-auth', got '{}'"
            raise MessageFlowError(error.format(client_auth.type))

    async def handshake_initiator(self, client_auth: ClientAuthMessage) -> None:
        """
        Disconnected
        MessageError
        MessageFlowError
        DowngradeError
        ServerKeyError
        """
        path, initiator = self.path, self.client
        assert path is not None
        assert initiator is not None

        # Handle client-auth
        self._handle_client_auth(client_auth)

        # Authenticated
        previous_initiator = path.set_initiator(initiator)
        if previous_initiator is not None:
            # Drop previous initiator using its job queue
            path.log.debug('Dropping previous initiator {}', previous_initiator)
            previous_initiator.log.debug('Dropping (another initiator connected)')
            self._drop_client(previous_initiator, CloseCode.drop_by_initiator)

        # Send new-initiator message if any responder is present
        responder_ids = path.get_responder_ids()
        coroutines = []  # type: List[Coroutine[Any, Any, None]]
        for responder_id in responder_ids:
            responder = path.get_responder(responder_id)

            # Create message and add send coroutine to job queue of the responder
            new_initiator = NewInitiatorMessage.create(responder_id)
            responder.log.debug('Enqueueing new-initiator message')
            coroutines.append(responder.jobs.enqueue(responder.send(new_initiator)))
        await asyncio.gather(*coroutines, loop=self._loop)

        # Send server-auth
        responder_ids = list(path.get_responder_ids())
        server_auth = ServerAuthMessage.create(
            INITIATOR_ADDRESS, initiator.cookie_in,
            sign_keys=len(self._server.keys) > 0, responder_ids=responder_ids)
        initiator.log.debug('Sending server-auth including responder ids')
        await initiator.send(server_auth)

    async def handshake_responder(self, client_hello: ClientHelloMessage) -> None:
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        DowngradeError
        ServerKeyError
        """
        path, responder = self.path, self.client
        assert path is not None
        assert responder is not None

        # Set key on client
        responder.set_client_key(
            ResponderPublicSessionKey(client_hello.client_public_key))

        # Receive client-auth
        client_auth = await responder.receive()
        if not isinstance(client_auth, ClientAuthMessage):
            error = "Expected 'client-auth', got '{}'"
            raise MessageFlowError(error.format(client_auth.type))

        # Handle client-auth
        self._handle_client_auth(client_auth)

        # Authenticated
        id_ = path.add_responder(responder)

        # Send new-responder message if initiator is present
        initiator = None  # type: Optional[PathClient]
        try:
            initiator = path.get_initiator()
        except KeyError:
            pass
        else:
            # Create message and add send coroutine to job queue of the initiator
            new_responder = NewResponderMessage.create(id_)
            initiator.log.debug('Enqueueing new-responder message')
            await initiator.jobs.enqueue(initiator.send(new_responder))

        # Send server-auth
        server_auth = ServerAuthMessage.create(
            ResponderAddress(responder.id), responder.cookie_in,
            sign_keys=len(self._server.keys) > 0,
            initiator_connected=initiator is not None)
        responder.log.debug('Sending server-auth without responder ids')
        await responder.send(server_auth)

    async def initiator_receive_loop(self) -> NoReturn:
        path, initiator = self.path, self.client
        assert path is not None
        assert initiator is not None
        while True:
            # Receive relay message or drop-responder
            message = await initiator.receive()

            # Relay
            if isinstance(message, RelayMessage):
                # Lookup responder
                responder = None  # type: Optional[PathClient]
                try:
                    responder_id = ResponderAddress(message.destination)
                    responder = path.get_responder(responder_id)
                except KeyError:
                    pass
                # Send to responder
                await self.relay_message(
                    responder, ClientAddress(message.destination), message)
            # Drop-responder
            elif isinstance(message, DropResponderMessage):
                # Lookup responder
                try:
                    responder = path.get_responder(message.responder_id)
                except KeyError:
                    log_message = 'Responder {} already dropped, nothing to do'
                    path.log.debug(log_message, message.responder_id)
                else:
                    # Drop responder using its job queue
                    path.log.debug(
                        'Dropping responder {}, reason: {}', responder, message.reason)
                    responder.log.debug(
                        'Dropping (requested by initiator), reason: {}', message.reason)
                    self._drop_client(responder, CloseCode(message.reason))
            else:
                error = "Expected relay message or 'drop-responder', got '{}'"
                raise MessageFlowError(error.format(message.type))

    async def responder_receive_loop(self) -> NoReturn:
        path, responder = self.path, self.client
        assert path is not None
        assert responder is not None
        while True:
            # Receive relay message
            message = await responder.receive()

            # Relay
            if isinstance(message, RelayMessage):
                # Lookup initiator
                initiator = None  # type: Optional[PathClient]
                try:
                    initiator = path.get_initiator()
                except KeyError:
                    pass
                # Send to initiator
                await self.relay_message(initiator, INITIATOR_ADDRESS, message)
            else:
                error = "Expected relay message, got '{}'"
                raise MessageFlowError(error.format(message.type))

    async def relay_message(
            self,
            destination: Optional[PathClient],
            destination_id: ClientAddress,
            message: RelayMessage,
    ) -> None:
        source = self.client
        assert source is not None

        # Prepare message
        source.log.debug('Packing relay message')
        message_id = MessageId(message.pack(source)[COOKIE_LENGTH:NONCE_LENGTH])

        async def send_error_message() -> None:
            assert source is not None
            # Create message and add send coroutine to job queue of the source
            error = SendErrorMessage.create(ClientAddress(source.id), message_id)
            source.log.info('Relaying failed, enqueuing send-error')
            await source.jobs.enqueue(source.send(error))

        # Destination not connected? Send 'send-error' to source
        if destination is None:
            error_message = ('Cannot relay message, no connection for '
                             'destination id 0x{:02x}')
            source.log.info(error_message, destination_id)
            await send_error_message()
            return

        # Add send task to job queue of the destination
        task = self._loop.create_task(destination.send(message))
        destination.log.debug('Enqueueing relayed message from 0x{:02x}', source.id)
        await destination.jobs.enqueue(task)

        # noinspection PyBroadException
        try:
            # Wait for send task to complete
            await asyncio.wait_for(task, RELAY_TIMEOUT, loop=self._loop)
        except asyncio.TimeoutError:
            # Timed out, send 'send-error' to source
            log_message = 'Sending relayed message to 0x{:02x} timed out'
            source.log.info(log_message, destination_id)
            await send_error_message()
        except Exception as exc:
            # Handle cancellation of the client
            if isinstance(exc, asyncio.CancelledError) and source.tasks.have_result:
                raise

            # An exception has been triggered while sending the message.
            # Note: We don't care about the actual exception as the job
            #       queue runner will also trigger that exception on the
            #       destination client's handler who will log what happened.
            log_message = 'Sending relayed message failed, receiver 0x{:02x} is gone'
            source.log.info(log_message, destination_id)
            await send_error_message()
        else:
            source.log.debug('Sending relayed message to 0x{:02x} successful',
                             destination.id)

    async def keep_alive_loop(self) -> NoReturn:
        """
        Disconnected
        PingTimeoutError
        """
        client = self.client
        assert client is not None
        while True:
            # Wait
            # noinspection PyTypeChecker
            await asyncio.sleep(client.keep_alive_interval, loop=self._loop)

            # Send ping and wait for pong
            client.log.debug('Ping')
            pong_future = await client.ping()
            try:
                await asyncio.wait_for(
                    client.wait_pong(pong_future), client.keep_alive_timeout,
                    loop=self._loop)
            except asyncio.TimeoutError:
                client.log.debug('Ping timed out')
                raise PingTimeoutError(str(client))
            else:
                client.log.debug('Pong')
                client.keep_alive_pings += 1

    def _handle_client_auth(self, client_auth: ClientAuthMessage) -> None:
        """
        MessageError
        DowngradeError
        ServerKeyError
        """
        client = self.client
        assert client is not None

        # Validate cookie and ensure no sub-protocol downgrade took place
        self._validate_cookie(client_auth.server_cookie, client.cookie_out)
        self._validate_subprotocol(client_auth.subprotocols)

        # Set the keep alive interval (if any)
        if client_auth.ping_interval is not None:
            client.log.debug(
                'Setting keep-alive interval to {}', client_auth.ping_interval)
            client.keep_alive_interval = client_auth.ping_interval

        # Set the public permanent key the client wants to use (or fallback to primary)
        server_keys_count = len(self._server.keys)
        if client_auth.server_key is not None:
            # No permanent key pair?
            if server_keys_count == 0:
                raise ServerKeyError('Server does not have a permanent public key')

            # Find the key instance
            server_key = self._server.keys.get(client_auth.server_key)
            if server_key is None:
                raise ServerKeyError(
                    'Server does not have the requested permanent public key')

            # Set the key instance on the client
            client.server_permanent_key = server_key
        elif server_keys_count > 0:
            # Use primary permanent key
            client.server_permanent_key = next(iter(self._server.keys.values()))

    def _validate_cookie(
            self,
            expected_cookie: ServerCookie,
            actual_cookie: ServerCookie,
    ) -> None:
        """
        MessageError
        """
        client = self.client
        assert client is not None
        client.log.debug('Validating cookie')
        if not util.consteq(expected_cookie, actual_cookie):
            raise MessageError('Cookies do not match')

    def _validate_subprotocol(
            self,
            client_subprotocols: ListOrTuple[ChosenSubProtocol],
    ) -> None:
        """
        MessageError
        DowngradeError
        """
        client = self.client
        assert client is not None
        client.log.debug(
            'Checking for subprotocol downgrade, client: {}, server: {}',
            client_subprotocols, self._server.subprotocols)
        chosen = websockets.WebSocketServerProtocol.select_subprotocol(
            client_subprotocols, self._server.subprotocols)
        if chosen != self.subprotocol.value:
            raise DowngradeError('Subprotocol downgrade detected')

    def _drop_client(self, client: PathClient, code: CloseCode) -> None:
        """
        Mark the client as closed, schedule the closing procedure on
        the client's job queue and remove it from the path.

        .. important:: This should only be called by clients dropping
                       another client or when the server is closing.

        Arguments:
            - `client`: The client to be dropped.
            - `close`: The close code.
        """
        # Drop the client
        client.drop(code)

        # Remove the client from the path
        path = self.path
        assert path is not None
        path.remove_client(client)


class Paths:
    __slots__ = ('_log', 'number', 'paths')

    def __init__(self) -> None:
        self._log = util.get_logger('paths')
        self.number = 0
        self.paths = {}  # type: Dict[InitiatorPublicPermanentKey, Path]

    def get(self, initiator_key: InitiatorPublicPermanentKey) -> Path:
        if self.paths.get(initiator_key) is None:
            self.number += 1
            self.paths[initiator_key] = Path(initiator_key, self.number, attached=True)
            self._log.debug('Created new path: {}', self.number)
        return self.paths[initiator_key]

    def clean(self, path: Path) -> None:
        if path.attached and path.empty:
            path.attached = False
            try:
                del self.paths[path.initiator_key]
            except KeyError:
                self._log.error('Path {} has already been removed', path.number)
            else:
                self._log.debug('Removed empty path: {}', path.number)


class Server:
    subprotocols = [
        SubProtocol.saltyrtc_v1.value
    ]  # type: ClassVar[Sequence[SubProtocol]]

    def __init__(
            self,
            keys: Optional[Sequence[ServerSecretPermanentKey]],
            paths: Paths,
            loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._log = util.get_logger('server')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # Protocol class
        self._protocol_class = ServerProtocol

        # WebSocket server instance
        self._server = None

        # Validate & store keys
        if keys is None:
            keys = []
        if len(keys) != len({key.pk for key in keys}):
            raise ServerKeyError('Repeated permanent keys')
        self.keys = OrderedDict(
            ((ServerPublicPermanentKey(key.pk), key) for key in keys))  # type: Keys

        # Store paths
        self.paths = paths

        # Store server protocols and closing task
        self.protocols = set()  # type: Set[ServerProtocol]
        self._close_task = None  # type: Optional[asyncio.Task[None]]

        # Event Registry
        self._events = EventRegistry()

    @property
    def server(self) -> websockets.server.WebSocketServer:
        return self._server

    @server.setter
    def server(self, server: websockets.server.WebSocketServer) -> None:
        self._server = server
        self._log.debug('Server instance: {}', server)

    async def handler(
            self,
            connection: websockets.WebSocketServerProtocol,
            ws_path: str,
    ) -> None:
        # Closing? Drop immediately
        if self._close_task is not None:
            await connection.close(CloseCode.going_away.value)
            return

        # Convert sub-protocol
        subprotocol = None  # type: Optional[SubProtocol]
        try:
            subprotocol = SubProtocol(connection.subprotocol)
        except ValueError:
            pass

        # Determine ServerProtocol instance by selected sub-protocol
        if subprotocol != SubProtocol.saltyrtc_v1:
            self._log.notice('Could not negotiate a sub-protocol, dropping client')
            # We need to close the connection manually as the client may choose
            # to ignore
            await connection.close(code=CloseCode.subprotocol_error.value)
            self.notify_disconnected(
                None, DisconnectedData(CloseCode.subprotocol_error.value))
        else:
            assert subprotocol is not None
            protocol = self._protocol_class(
                self, subprotocol, connection, ws_path, loop=self._loop)
            await protocol.handler_task

    def register(self, protocol: ServerProtocol) -> None:
        self.protocols.add(protocol)
        self._log.debug('Protocol registered: {}', protocol)

    def unregister(self, protocol: ServerProtocol) -> None:
        self.protocols.remove(protocol)
        self._log.debug('Protocol unregistered: {}', protocol)

    def register_event_callback(self, event: Event, callback: EventCallback) -> None:
        """
        Register a new event callback.
        """
        self._events.register(event, callback)

    def notify_initiator_connected(self, path: PathHex) -> None:
        self._raise_event(Event.initiator_connected, path, None)

    def notify_responder_connected(self, path: PathHex) -> None:
        self._raise_event(Event.responder_connected, path, None)

    def notify_disconnected(
            self,
            path: Optional[PathHex],
            data: DisconnectedData,
    ) -> None:
        self._raise_event(Event.disconnected, path, data)

    def _raise_event(
            self,
            event: Event,
            path: Optional[PathHex],
            data: EventData,
    ) -> None:
        """
        Raise an event and invoke all registered event callbacks.

        Arguments:
            - `event`: Event to be raised.
            - `path`: Associated path in hexadecimal representation or
              `None` if not available.
            - `data`: Additional data for the event as explained for
              :class:`EventRegistry`.
        """
        for callback in self._events.get_callbacks(event):
            coroutine = callback(event, path, data)
            log_handler = functools.partial(
                self._log.exception, 'Unhandled exception in event handler:')
            # noinspection PyTypeChecker
            self._loop.create_task(util.log_exception(coroutine, log_handler))

    def close(self) -> None:
        """
        Close open connections and the server.
        """
        if self._close_task is None:
            log_handler = functools.partial(
                self._log.exception, 'Exception while closing:')
            # noinspection PyTypeChecker
            self._close_task = self._loop.create_task(
                util.log_exception(self._close_after_all_protocols_closed(), log_handler))

    async def wait_closed(self) -> None:
        """
        Wait until all connections and the server itself has been
        closed.
        """
        await self.server.wait_closed()

    async def _close_after_all_protocols_closed(
            self,
            timeout: Optional[float] = None,
    ) -> None:
        # Schedule closing all protocols
        self._log.info('Closing protocols')
        if len(self.protocols) > 0:
            async def _close_and_wait() -> None:
                # Wait until all connections have been scheduled to be closed
                for protocol in self.protocols:
                    protocol.close(CloseCode.going_away)

                # Wait until all protocols have returned
                handler_tasks = [protocol.handler_task for protocol in self.protocols]
                await asyncio.gather(*handler_tasks, loop=self._loop)

            await asyncio.wait_for(_close_and_wait(), timeout, loop=self._loop)

        # Now we can close the server
        self._log.info('Closing server')
        self.server.close()
