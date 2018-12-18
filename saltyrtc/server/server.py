import asyncio
import binascii
from collections import OrderedDict
from typing import (
    Dict,
    List,
)

import websockets

from . import util
from .common import (
    COOKIE_LENGTH,
    NONCE_LENGTH,
    RELAY_TIMEOUT,
    AddressType,
    ClientState,
    CloseCode,
    MessageType,
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
    DisconnectedMessage,
    NewInitiatorMessage,
    NewResponderMessage,
    RawMessage,
    SendErrorMessage,
    ServerAuthMessage,
    ServerHelloMessage,
)
from .protocol import (
    Path,
    PathClient,
    PathClientTasks,
    Protocol,
)

try:
    from collections.abc import Coroutine
except ImportError:  # python 3.4
    # noinspection PyPackageRequirements
    from backports_abc import Coroutine

__all__ = (
    'serve',
    'ServerProtocol',
    'Paths',
    'Server',
)

_TASK_QUEUE_JOIN_TIMEOUT = 10.0


@asyncio.coroutine
def serve(
        ssl_context, keys, paths=None, host=None, port=8765, loop=None,
        event_callbacks: Dict[Event, List[Coroutine]] = None, server_class=None,
        ws_kwargs=None,
):
    """
    Start serving SaltyRTC Signalling Clients.

    Arguments:
        - `ssl_context`: An `ssl.SSLContext` instance for WSS.
        - `keys`: A sorted iterable of :class:`libnacl.public.SecretKey`
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
        server_class = Server
    server = server_class(keys, paths, loop=loop)

    # Register event callbacks
    if event_callbacks is not None:
        for event, callbacks in event_callbacks.items():
            for callback in callbacks:
                server.register_event_callback(event, callback)

    # Prepare arguments for the WS server
    if ws_kwargs is None:
        ws_kwargs = {}
    ws_kwargs['ssl'] = ssl_context
    ws_kwargs['host'] = host
    ws_kwargs['port'] = port
    ws_kwargs.setdefault('compression', None)
    ws_kwargs['ping_interval'] = None  # Disable the keep-alive of the transport library
    ws_kwargs['subprotocols'] = server.subprotocols

    # Start WS server
    ws_server = yield from websockets.serve(server.handler, **ws_kwargs)

    # Set WS server instance
    server.server = ws_server

    # Return server
    return server


class ServerProtocol(Protocol):
    __slots__ = (
        '_log',
        '_loop',
        '_server',
        'subprotocol',
        'path',
        'client',
        'handler_task'
    )

    def __init__(self, server, subprotocol, connection, ws_path, loop=None):
        self._log = util.get_logger('server.protocol')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # Server instance and subprotocol
        self._server = server
        self.subprotocol = subprotocol

        # Path and client instance
        self.path = None
        self.client = None
        self._log.debug('New connection on WS path {}', ws_path)

        # Get path and client instance as early as possible
        try:
            path, client = self.get_path_client(connection, ws_path)
        except PathError as exc:
            self._log.notice('Closing due to path error: {}', exc)

            @asyncio.coroutine
            def close_with_protocol_error():
                yield from connection.close(code=CloseCode.protocol_error.value)
                self._server.raise_event(
                    Event.disconnected, None, CloseCode.protocol_error.value)
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
        self.handler_task = asyncio.ensure_future(handler_coroutine, loop=self._loop)

    @asyncio.coroutine
    def handler(self):
        client, path = self.client, self.path

        # Handle client until disconnected or an exception occurred
        hex_path = binascii.hexlify(self.path.initiator_key).decode('ascii')
        close_future = asyncio.Future(loop=self._loop)

        try:
            yield from self.handle_client()
        except Disconnected as exc:
            client.log.info('Connection closed (code: {})', exc.reason)
            close_future.set_result(None)
            self._server.raise_event(Event.disconnected, hex_path, exc.reason)
        except PingTimeoutError:
            client.log.info('Closing because of a ping timeout')
            close_future = client.close(CloseCode.timeout)
            self._server.raise_event(
                Event.disconnected, hex_path, CloseCode.timeout)
        except SlotsFullError as exc:
            client.log.notice('Closing because all path slots are full: {}', exc)
            close_future = client.close(code=CloseCode.path_full_error.value)
            self._server.raise_event(
                Event.disconnected, hex_path, CloseCode.path_full_error.value)
        except ServerKeyError as exc:
            client.log.notice('Closing due to server key error: {}', exc)
            close_future = client.close(code=CloseCode.invalid_key.value)
            self._server.raise_event(
                Event.disconnected, hex_path, CloseCode.invalid_key.value)
        except InternalError as exc:
            client.log.exception('Closing due to an internal error:', exc)
            close_future = client.close(code=CloseCode.internal_error.value)
            self._server.raise_event(
                Event.disconnected, hex_path, CloseCode.internal_error.value)
        except SignalingError as exc:
            client.log.notice('Closing due to protocol error: {}', exc)
            close_future = client.close(code=CloseCode.protocol_error.value)
            self._server.raise_event(
                Event.disconnected, hex_path, CloseCode.protocol_error.value)
        except Exception as exc:
            client.log.exception('Closing due to exception:', exc)
            close_future = client.close(code=CloseCode.internal_error.value)
            self._server.raise_event(
                Event.disconnected, hex_path, CloseCode.internal_error.value)
        else:
            # Note: This should not ever happen since 'handle_client'
            #       contains an infinite loop that only stops due to an exception.
            client.log.error('Client closed without exception')
            close_future.set_result(None)

        # Schedule closing of the client
        # Note: This ensures the client is closed soon even if the task queue is holding
        #       us up.
        close_future = asyncio.ensure_future(close_future, loop=self._loop)

        # Wait until all queued tasks have been processed
        # Note: This ensure that a send-error message (and potentially other messages)
        #       are enqueued towards other clients before the disconnect message.
        client.log.debug('Joining task queue')
        try:
            yield from asyncio.wait_for(
                client.join_task_queue(), _TASK_QUEUE_JOIN_TIMEOUT, loop=self._loop)
        except asyncio.TimeoutError:
            client.log.error(
                'Task queue did not close after {} seconds', _TASK_QUEUE_JOIN_TIMEOUT)
        else:
            client.log.debug('Task queue closed')

        # Send disconnected message if client was authenticated
        if client.state == ClientState.authenticated:
            # Initiator: Send to all responders
            if client.type == AddressType.initiator:
                responder_ids = path.get_responder_ids()
                coroutines = []
                for responder_id in responder_ids:
                    responder = path.get_responder(responder_id)

                    # Create message and add send coroutine to task queue of the responder
                    message = DisconnectedMessage.create(
                        AddressType.server, responder_id, client.id)
                    responder.log.debug('Enqueueing disconnected message')
                    coroutines.append(responder.enqueue_task(responder.send(message)))
                try:
                    yield from asyncio.gather(*coroutines, loop=self._loop)
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
                    # Create message and add send coroutine to task queue of the
                    # initiator
                    message = DisconnectedMessage.create(
                        AddressType.server, initiator.id, client.id)
                    initiator.log.debug('Enqueueing disconnected message')
                    try:
                        yield from initiator.enqueue_task(initiator.send(message))
                    except Exception as exc:
                        description = 'Error while dispatching disconnected message' \
                                      'to initiator:'
                        client.log.exception(description, exc)
            else:
                client.log.error('Invalid address type: {}', client.type)
        else:
            client.log.debug(
                'Skipping disconnected message due to {} state', client.state.name)

        # Wait for the connection to be closed
        yield from close_future
        client.log.debug('WS connection closed')

        # Remove protocol from server and stop
        self._server.unregister(self)
        client.log.debug('Worker stopped')

    @asyncio.coroutine
    def close(self, code):
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
            yield from self._drop_client(self.client, code)

    def get_path_client(self, connection, ws_path):
        # Extract public key from path
        initiator_key = ws_path[1:]

        # Validate key
        if len(initiator_key) != self.PATH_LENGTH:
            raise PathError('Invalid path length: {}'.format(len(initiator_key)))
        try:
            initiator_key = binascii.unhexlify(initiator_key)
        except (binascii.Error, ValueError) as exc:
            raise PathError('Could not unhexlify path') from exc

        # Get path instance
        path = self._server.paths.get(initiator_key)

        # Create client instance
        client = PathClient(connection, path.number, initiator_key,
                            loop=self._loop)

        # Return path and client
        return path, client

    @asyncio.coroutine
    def handle_client(self):
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

        # Do handshake
        client.log.debug('Starting handshake')
        yield from self.handshake()
        client.log.info('Handshake completed')

        # Task: Execute enqueued tasks
        client.log.debug('Starting to poll for enqueued tasks')
        task_loop = self.task_loop()

        # Check if the client is still connected to the path or has already been dropped.
        # Note: This can happen when the client is being picked up and dropped by another
        #       client while running the handshake. To prevent other race conditions, we
        #       have to add the client instance to the path early during the handshake.
        is_connected = path.has_client(client)

        # Task: Poll for messages
        hex_path = binascii.hexlify(path.initiator_key).decode('ascii')
        receive_loop = None
        if client.type == AddressType.initiator:
            self._server.raise_event(Event.initiator_connected, hex_path)
            if is_connected:
                client.log.debug('Starting runner for initiator')
                receive_loop = self.initiator_receive_loop()
        elif client.type == AddressType.responder:
            self._server.raise_event(Event.responder_connected, hex_path)
            if is_connected:
                client.log.debug('Starting runner for responder')
                receive_loop = self.responder_receive_loop()
        else:
            raise ValueError('Invalid address type: {}'.format(client.type))

        # Task: Keep alive
        if is_connected:
            client.log.debug('Starting keep-alive task')
            keep_alive_loop = self.keep_alive_loop()
        else:
            keep_alive_loop = None

        # Move the tasks into a context and store it on the path
        client.tasks = PathClientTasks(
            task_loop=task_loop,
            receive_loop=receive_loop,
            keep_alive_loop=keep_alive_loop,
            loop=self._loop
        )

        # Wait until complete
        #
        # Note: We also add the task loop into this list to catch any errors that bubble
        #       up in tasks of this client.
        #
        # Warning: This is probably the most complicated piece of code in the server.
        #          Avoid touching this!
        tasks = set(client.tasks.valid)
        while True:
            done, pending = yield from asyncio.wait(
                tasks, loop=self._loop, return_when=asyncio.FIRST_COMPLETED)
            is_connected = path.has_client(client)
            exc = None
            for task in done:
                client.log.debug('Task done {}, connected={}', task, is_connected)

                # Determine the exception to be raised
                # Note: The first task will set the exception that will be raised.
                if task.cancelled():
                    if task != client.tasks.task_loop and not is_connected:
                        # If the client has been dropped, we need to wait for the task
                        # loop to return. So, remove the task from the list and continue.
                        tasks.remove(task)
                        break
                    if exc is None:
                        exc = InternalError('A vital task has been cancelled')
                    client.log.error('Task {} has been cancelled', task)
                    continue

                task_exc = task.exception()
                if task_exc is None:
                    connection_closed_future = client.connection_closed_future
                    if not connection_closed_future.done():
                        client.log.error('Task {} returned unexpectedly', task)
                        task_exc = InternalError('A task returned unexpectedly')
                    else:
                        # Note: This can happen in case a task returned due to the
                        #       connection becoming closed. Since this doesn't raise an
                        #       exception, we need to do it ourselves.
                        task_exc = Disconnected(connection_closed_future.result())

                if exc is None:
                    exc = task_exc

            # Continue if we have no exception
            # Note: This may only happen in case the client has been dropped and we need
            #       to wait for the task loop to return.
            if exc is None:
                continue

            # Cancel pending tasks
            for pending_task in pending:
                client.log.debug('Cancelling task {}', pending_task)
                pending_task.cancel()

            # Cancel the task queue and remove client from path
            # Note: Removing the client needs to be done here since the re-raise hands
            #       the task back into the event loop allowing other tasks to get the
            #       client's path instance from the path while it is already effectively
            #       disconnected.
            client.cancel_task_queue()
            path = self.path
            try:
                path.remove_client(client)
            except KeyError:
                # We can safely ignore this since clients will be removed immediately
                # from the path in case they are being dropped by another client.
                pass
            self._server.paths.clean(path)

            # Finally, raise the exception
            raise exc

    @asyncio.coroutine
    def handshake(self):
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        DowngradeError
        ServerKeyError
        """
        client = self.client

        # Send server-hello
        message = ServerHelloMessage.create(
            AddressType.server, client.id, client.server_key.pk)
        client.log.debug('Sending server-hello')
        yield from client.send(message)

        # Receive client-hello or client-auth
        client.log.debug('Waiting for client-hello or client-auth')
        message = yield from client.receive()
        if message.type == MessageType.client_auth:
            client.log.debug('Received client-auth')
            # Client is the initiator
            client.type = AddressType.initiator
            yield from self.handshake_initiator(message)
        elif message.type == MessageType.client_hello:
            client.log.debug('Received client-hello')
            # Client is a responder
            client.type = AddressType.responder
            yield from self.handshake_responder(message)
        else:
            error = "Expected 'client-hello' or 'client-auth', got '{}'"
            raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def handshake_initiator(self, message):
        """
        Disconnected
        MessageError
        MessageFlowError
        DowngradeError
        ServerKeyError
        """
        path, initiator = self.path, self.client

        # Handle client-auth
        self._handle_client_auth(message)

        # Authenticated
        previous_initiator = path.set_initiator(initiator)
        if previous_initiator is not None:
            # Drop previous initiator using its task queue
            path.log.debug('Dropping previous initiator {}', previous_initiator)
            previous_initiator.log.debug('Dropping (another initiator connected)')
            self._drop_client(previous_initiator, CloseCode.drop_by_initiator)

        # Send new-initiator message if any responder is present
        responder_ids = path.get_responder_ids()
        coroutines = []
        for responder_id in responder_ids:
            responder = path.get_responder(responder_id)

            # Create message and add send coroutine to task queue of the responder
            message = NewInitiatorMessage.create(AddressType.server, responder_id)
            responder.log.debug('Enqueueing new-initiator message')
            coroutines.append(responder.enqueue_task(responder.send(message)))
        yield from asyncio.gather(*coroutines, loop=self._loop)

        # Send server-auth
        responder_ids = list(path.get_responder_ids())
        message = ServerAuthMessage.create(
            AddressType.server, initiator.id, initiator.cookie_in,
            sign_keys=len(self._server.keys) > 0, responder_ids=responder_ids)
        initiator.log.debug('Sending server-auth including responder ids')
        yield from initiator.send(message)

    @asyncio.coroutine
    def handshake_responder(self, message):
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        DowngradeError
        ServerKeyError
        """
        path, responder = self.path, self.client

        # Set key on client
        responder.set_client_key(message.client_public_key)

        # Receive client-auth
        message = yield from responder.receive()
        if message.type != MessageType.client_auth:
            error = "Expected 'client-auth', got '{}'"
            raise MessageFlowError(error.format(message.type))

        # Handle client-auth
        self._handle_client_auth(message)

        # Authenticated
        id_ = path.add_responder(responder)

        # Send new-responder message if initiator is present
        try:
            initiator = path.get_initiator()
        except KeyError:
            initiator = None
        else:
            # Create message and add send coroutine to task queue of the initiator
            message = NewResponderMessage.create(AddressType.server, initiator.id, id_)
            initiator.log.debug('Enqueueing new-responder message')
            yield from initiator.enqueue_task(initiator.send(message))

        # Send server-auth
        message = ServerAuthMessage.create(
            AddressType.server, responder.id, responder.cookie_in,
            sign_keys=len(self._server.keys) > 0,
            initiator_connected=initiator is not None)
        responder.log.debug('Sending server-auth without responder ids')
        yield from responder.send(message)

    @asyncio.coroutine
    def task_loop(self):
        client = self.client
        while not client.connection_closed_future.done():
            # Get a task from the queue
            task = yield from client.dequeue_task()

            # Wait and handle exceptions
            client.log.debug('Waiting for task to complete {}', task)
            try:
                yield from task
            except Exception as exc:
                if isinstance(exc, asyncio.CancelledError):
                    client.log.debug('Cancelling active task {}', task)
                else:
                    client.log.debug('Stopping active task {}, ', task)
                if asyncio.iscoroutine(task):
                    task.close()
                    client.task_done(task)
                else:
                    task.add_done_callback(client.task_done)
                raise
            client.task_done(task)

    @asyncio.coroutine
    def initiator_receive_loop(self):
        path, initiator = self.path, self.client
        while not initiator.connection_closed_future.done():
            # Receive relay message or drop-responder
            message = yield from initiator.receive()

            # Relay
            if isinstance(message, RawMessage):
                # Lookup responder
                try:
                    responder = path.get_responder(message.destination)
                except KeyError:
                    responder = None
                # Send to responder
                yield from self.relay_message(responder, message.destination, message)
            # Drop-responder
            elif message.type == MessageType.drop_responder:
                # Lookup responder
                try:
                    responder = path.get_responder(message.responder_id)
                except KeyError:
                    log_message = 'Responder {} already dropped, nothing to do'
                    path.log.debug(log_message, message.responder_id)
                else:
                    # Drop responder using its task queue
                    path.log.debug(
                        'Dropping responder {}, reason: {}', responder, message.reason)
                    responder.log.debug(
                        'Dropping (requested by initiator), reason: {}', message.reason)
                    self._drop_client(responder, message.reason.value)
            else:
                error = "Expected relay message or 'drop-responder', got '{}'"
                raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def responder_receive_loop(self):
        path, responder = self.path, self.client
        while not responder.connection_closed_future.done():
            # Receive relay message
            message = yield from responder.receive()

            # Relay
            if isinstance(message, RawMessage):
                # Lookup initiator
                try:
                    initiator = path.get_initiator()
                except KeyError:
                    initiator = None
                # Send to initiator
                yield from self.relay_message(initiator, AddressType.initiator, message)
            else:
                error = "Expected relay message, got '{}'"
                raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def relay_message(self, destination, destination_id, message):
        source = self.client

        # Prepare message
        source.log.debug('Packing relay message')
        message_id = message.pack(source)[COOKIE_LENGTH:NONCE_LENGTH]

        @asyncio.coroutine
        def send_error_message():
            # Create message and add send coroutine to task queue of the source
            error = SendErrorMessage.create(
                AddressType.server, source.id, message_id)
            source.log.info('Relaying failed, enqueuing send-error')
            yield from source.enqueue_task(source.send(error))

        # Destination not connected? Send 'send-error' to source
        if destination is None:
            error_message = ('Cannot relay message, no connection for '
                             'destination id 0x{:02x}')
            source.log.info(error_message, destination_id)
            yield from send_error_message()
            return

        # Add send task to task queue of the source
        task = asyncio.ensure_future(destination.send(message), loop=self._loop)
        destination.log.debug('Enqueueing relayed message from 0x{:02x}', source.id)
        yield from destination.enqueue_task(task)

        # noinspection PyBroadException
        try:
            # Wait for send task to complete
            yield from asyncio.wait_for(task, RELAY_TIMEOUT, loop=self._loop)
        except asyncio.TimeoutError:
            # Timed out, send 'send-error' to source
            log_message = 'Sending relayed message to 0x{:02x} timed out'
            source.log.info(log_message, destination_id)
            yield from send_error_message()
        except Exception:
            # An exception has been triggered while sending the message.
            # Note: We don't care about the actual exception as the task
            #       loop will also trigger that exception on the
            #       destination client's handler who will log what happened.
            log_message = 'Sending relayed message failed, receiver 0x{:02x} is gone'
            source.log.info(log_message, destination_id)
            yield from send_error_message()
        else:
            source.log.debug('Sending relayed message to 0x{:02x} successful',
                             destination.id)

    @asyncio.coroutine
    def keep_alive_loop(self):
        """
        Disconnected
        PingTimeoutError
        """
        client = self.client
        while not client.connection_closed_future.done():
            # Wait
            yield from asyncio.sleep(client.keep_alive_interval, loop=self._loop)

            # Send ping and wait for pong
            client.log.debug('Ping')
            pong_future = yield from client.ping()
            try:
                yield from asyncio.wait_for(
                    pong_future, client.keep_alive_timeout, loop=self._loop)
            except asyncio.TimeoutError:
                client.log.debug('Ping timed out')
                raise PingTimeoutError(client)
            else:
                client.log.debug('Pong')
                client.keep_alive_pings += 1

    def _handle_client_auth(self, message):
        """
        MessageError
        DowngradeError
        ServerKeyError
        """
        client = self.client

        # Validate cookie and ensure no sub-protocol downgrade took place
        self._validate_cookie(message.server_cookie, client.cookie_out)
        self._validate_subprotocol(message.subprotocols)

        # Set the keep alive interval (if any)
        if message.ping_interval is not None:
            client.log.debug('Setting keep-alive interval to {}', message.ping_interval)
            client.keep_alive_interval = message.ping_interval

        # Set the public permanent key the client wants to use (or fallback to primary)
        server_keys_count = len(self._server.keys)
        if message.server_key is not None:
            # No permanent key pair?
            if server_keys_count == 0:
                raise ServerKeyError('Server does not have a permanent public key')

            # Find the key instance
            server_key = self._server.keys.get(message.server_key)
            if server_key is None:
                raise ServerKeyError(
                    'Server does not have the requested permanent public key')

            # Set the key instance on the client
            client.server_permanent_key = server_key
        elif server_keys_count > 0:
            # Use primary permanent key
            client.server_permanent_key = next(iter(self._server.keys.values()))

    def _validate_cookie(self, expected_cookie, actual_cookie):
        """
        MessageError
        """
        self.client.log.debug('Validating cookie')
        if not util.consteq(expected_cookie, actual_cookie):
            raise MessageError('Cookies do not match')

    def _validate_subprotocol(self, client_subprotocols):
        """
        MessageError
        DowngradeError
        """
        self.client.log.debug(
            'Checking for subprotocol downgrade, client: {}, server: {}',
            client_subprotocols, self._server.subprotocols)
        chosen = websockets.WebSocketServerProtocol.select_subprotocol(
            client_subprotocols, self._server.subprotocols)
        if chosen != self.subprotocol.value:
            raise DowngradeError('Subprotocol downgrade detected')

    def _drop_client(self, client, code):
        """
        Mark the client as closed, schedule the closing procedure on
        the client's task queue, remove it from the path and return the
        drop operation in form of a :class:`asyncio.Task`.

        .. important:: This should only be called by clients dropping
                       another client or when the server is closing.

        Arguments:
            - `client`: The client to be dropped.
            - `close`: The close code.
        """
        # Drop the client
        drop_task = client.drop(code)

        # Remove the client from the path
        path = self.path
        path.remove_client(client)

        return drop_task


class Paths:
    __slots__ = ('_log', 'number', 'paths')

    def __init__(self):
        self._log = util.get_logger('paths')
        self.number = 0
        self.paths = {}

    def get(self, initiator_key):
        if self.paths.get(initiator_key) is None:
            self.number += 1
            self.paths[initiator_key] = Path(initiator_key, self.number, attached=True)
            self._log.debug('Created new path: {}', self.number)
        return self.paths[initiator_key]

    def clean(self, path):
        if path.attached and path.empty:
            path.attached = False
            try:
                del self.paths[path.initiator_key]
            except KeyError:
                self._log.error('Path {} has already been removed', path.number)
            else:
                self._log.debug('Removed empty path: {}', path.number)


class Server(asyncio.AbstractServer):
    subprotocols = [
        SubProtocol.saltyrtc_v1.value
    ]

    def __init__(self, keys, paths, loop=None):
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
        self.keys = OrderedDict(((key.pk, key) for key in keys))

        # Store paths
        self.paths = paths

        # Store server protocols and closing task
        self.protocols = set()
        self._close_task = None

        # Event Registry
        self._events = EventRegistry()

    @property
    def server(self):
        return self._server

    @server.setter
    def server(self, server):
        self._server = server
        self._log.debug('Server instance: {}', server)

    @asyncio.coroutine
    def handler(self, connection, ws_path):
        # Closing? Drop immediately
        if self._close_task is not None:
            yield from connection.close(CloseCode.going_away.value)
            return

        # Convert sub-protocol
        try:
            subprotocol = SubProtocol(connection.subprotocol)
        except ValueError:
            subprotocol = None

        # Determine ServerProtocol instance by selected sub-protocol
        if subprotocol != SubProtocol.saltyrtc_v1:
            self._log.notice('Could not negotiate a sub-protocol, dropping client')
            # We need to close the connection manually as the client may choose
            # to ignore
            yield from connection.close(code=CloseCode.subprotocol_error.value)
            self.raise_event(Event.disconnected, None, CloseCode.subprotocol_error.value)
        else:
            protocol = self._protocol_class(
                self, subprotocol, connection, ws_path, loop=self._loop)
            yield from protocol.handler_task

    def register(self, protocol):
        self.protocols.add(protocol)
        self._log.debug('Protocol registered: {}', protocol)

    def unregister(self, protocol):
        self.protocols.remove(protocol)
        self._log.debug('Protocol unregistered: {}', protocol)

    def register_event_callback(self, event: Event, callback: Coroutine):
        """
        Register a new event callback.
        """
        self._events.register(event, callback)

    def raise_event(self, event: Event, *data):
        """
        Raise an event and call all registered event callbacks.
        """
        for callback in self._events.get_callbacks(event):
            asyncio.ensure_future(callback(event, *data), loop=self._loop)

    def close(self):
        """
        Close open connections and the server.
        """
        if self._close_task is None:
            self._close_task = asyncio.ensure_future(
                self._close_after_all_protocols_closed(), loop=self._loop)

    @asyncio.coroutine
    def wait_closed(self):
        """
        Wait until all connections and the server itself has been
        closed.
        """
        yield from self.server.wait_closed()

    @asyncio.coroutine
    def _close_after_all_protocols_closed(self, timeout=None):
        # Schedule closing all protocols
        self._log.info('Closing protocols')
        if len(self.protocols) > 0:
            @asyncio.coroutine
            def _close_and_wait():
                # Wait until all connections have been scheduled to be closed
                tasks = [protocol.close(CloseCode.going_away.value)
                         for protocol in self.protocols]
                yield from asyncio.gather(*tasks, loop=self._loop)

                # Wait until all protocols have returned
                tasks = [protocol.handler_task for protocol in self.protocols]
                yield from asyncio.gather(*tasks, loop=self._loop)

            yield from asyncio.wait_for(_close_and_wait(), timeout, loop=self._loop)

        # Now we can close the server
        self._log.info('Closing server')
        self.server.close()
