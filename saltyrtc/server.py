import asyncio
import binascii
import inspect

import websockets

from . import util
from .exception import *
from .common import (
    RELAY_TIMEOUT,
    SubProtocol,
    CloseCode,
    AddressType,
    MessageType,
)
from .protocol import (
    Path,
    PathClient,
    Protocol,
)
from .message import (
    ServerHelloMessage,
    ServerAuthMessage,
    NewInitiatorMessage,
    NewResponderMessage,
    SendErrorMessage,
    RawMessage,
)

__all__ = (
    'serve',
    'ServerProtocol',
    'Paths',
    'Server',
)


@asyncio.coroutine
def serve(ssl_context, key, paths=None, host=None, port=8765, loop=None):
    """
    Start serving SaltyRTC Signalling Clients.

    Arguments:
        - `ssl_context`: An `ssl.SSLContext` instance for WSS.
        - `key`: A :class:`libnacl.public.SecretKey` instance
          containing the permanent private key of the server.
        - `paths`: A :class:`Paths` instance that maps path names to
          :class:`Path` instances. Can be used to share paths on
          multiple WebSockets. Defaults to an empty paths instance.
        - `host`: The hostname or IP address the server will listen on.
          Defaults to all interfaces.
        - `port`: The port the client should connect to. Defaults to
          `8765`.
        - `loop`: A :class:`asyncio.BaseEventLoop` instance or `None`
          if the default event loop should be used.


    """
    if loop is None:
        loop = asyncio.get_event_loop()

    # Create paths if not given
    if paths is None:
        paths = Paths()

    # Create server
    server = Server(key, paths, loop=loop)

    # Start server
    ws_server = yield from websockets.serve(
        server.handler,
        ssl=ssl_context,
        host=host,
        port=port,
        subprotocols=server.subprotocols
    )

    # Set server instance
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

    def __init__(self, server, subprotocol, loop=None):
        self._log = util.get_logger('server.protocol')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # Server instance and subprotocol
        self._server = server
        self.subprotocol = subprotocol

        # Path and client instance
        self.path = None
        self.client = None

        # Handler task that is set after 'connection_made' has been called
        self.handler_task = None

        # Determine subprotocol selection function
        # Might be a static method, might be a normal method, see
        # https://github.com/aaugustin/websockets/pull/132
        protocol = websockets.WebSocketServerProtocol
        select_subprotocol = inspect.getattr_static(protocol, 'select_subprotocol')
        if isinstance(select_subprotocol, staticmethod):
            self._select_subprotocol = protocol.select_subprotocol
        else:
            def _select_subprotocol(client_subprotocols, server_subprotocols):
                # noinspection PyTypeChecker
                return protocol.select_subprotocol(
                    None, client_subprotocols, server_subprotocols)
            self._select_subprotocol = _select_subprotocol

    def connection_made(self, connection, ws_path):
        self.handler_task = self._loop.create_task(self.handler(connection, ws_path))

    @asyncio.coroutine
    def close(self, code=1000):
        # Note: The client will be set as early as possible without any yielding.
        #       Thus, self.client is either set and can be closed or the connection
        #       is already closing (see the corresponding lines in 'handler' and
        #       'get_path_client')
        if self.client is not None:
            yield from self.client.close(code=code)

    @asyncio.coroutine
    def handler(self, connection, ws_path):
        self._log.debug('New connection on WS path {}', ws_path)

        # Get path and client instance as early as possible
        try:
            path, client = self.get_path_client(connection, ws_path)
        except PathError as exc:
            self._log.notice('Closing due to path error: {}', exc)
            yield from connection.close(code=CloseCode.protocol_error.value)
            return
        client.log.info('Connection established')
        client.log.debug('Worker started')

        # Store path and client
        self.path = path
        self.client = client
        self._server.register(self)

        # Handle client until disconnected or an exception occurred
        try:
            yield from self.handle_client()
        except Disconnected:
            client.log.info('Connection closed by remote')
        except SlotsFullError as exc:
            client.log.notice('Closing because all path slots are full: {}', exc)
            yield from client.close(code=CloseCode.path_full_error.value)
        except SignalingError as exc:
            client.log.notice('Closing due to protocol error: {}', exc)
            yield from client.close(code=CloseCode.protocol_error.value)
        except Exception as exc:
            client.log.exception('Closing due to exception:', exc)
            yield from client.close(code=CloseCode.internal_error.value)

        # Remove client from path
        path.remove_client(client)

        # Remove protocol from server and stop
        self._server.unregister(self)
        client.log.debug('Worker stopped')

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
        client = PathClient(connection, path.number, initiator_key, self._server.key)

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
        """
        path, client = self.path, self.client

        # Do handshake
        client.log.debug('Starting handshake')
        yield from self.handshake()
        client.log.info('Handshake completed')

        # Task: Execute enqueued tasks
        client.log.debug('Starting poll for enqueued tasks task')
        tasks = [self.task_loop()]

        # Task: Poll for messages
        if client.type == AddressType.initiator:
            client.log.debug('Starting runner for initiator')
            tasks.append(self.initiator_receive_loop())
        elif client.type == AddressType.responder:
            client.log.debug('Starting runner for responder')
            tasks.append(self.responder_receive_loop())
        else:
            raise ValueError('Invalid address type: {}'.format(client.type))

        # Task: Keep alive (if requested)
        client.log.debug('Starting keep-alive task')
        tasks.append(self.keep_alive_loop())

        # Wait until complete
        tasks = [self._loop.create_task(coroutine) for coroutine in tasks]
        done, pending = yield from asyncio.wait(
            tasks, loop=self._loop, return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            exc = task.exception()

            # Cancel pending tasks
            for pending_task in pending:
                client.log.debug('Cancelling task {}', pending_task)
                pending_task.cancel()

            # Connection closed?
            if not client.connection_closed.done():
                # Raise (or re-raise)
                if exc is None:
                    client.log.error('Task {} returned unexpectedly', task)
                    raise SignalingError('A task returned unexpectedly')
                raise exc

    @asyncio.coroutine
    def handshake(self):
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        DowngradeError
        """
        path, client = self.path, self.client

        # Send server-hello
        message = ServerHelloMessage.create(
            AddressType.server, client.id, client.server_key.pk)
        client.log.debug('Sending server-hello')
        yield from client.send(message)

        # Receive client-hello or client-auth
        client.log.debug('Waiting for client-hello')
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
        """
        path, initiator = self.path, self.client

        # Validate cookie and ensure no sub-protocol downgrade took place
        self._validate_cookie(message.server_cookie, initiator.cookie_out)
        self._validate_subprotocol(message.subprotocols)

        # Authenticated
        previous_initiator = path.set_initiator(initiator)
        if previous_initiator is not None:
            # Drop previous initiator using the task queue of the previous initiator
            path.log.debug('Dropping previous initiator {}', previous_initiator)
            previous_initiator.log.debug('Dropping (another initiator connected)')
            coro = previous_initiator.close(code=CloseCode.drop_by_initiator.value)
            yield from previous_initiator.enqueue_task(coro)

        # Send new-initiator message if any responder is present
        responder_ids = path.get_responder_ids()
        for responder_id in responder_ids:
            responder = path.get_responder(responder_id)

            # Create message and add send coroutine to task queue of the responder
            message = NewInitiatorMessage.create(AddressType.server, responder_id)
            responder.log.debug('Enqueueing new-initiator message')
            yield from responder.enqueue_task(responder.send(message))

        # Send server-auth
        responder_ids = path.get_responder_ids()
        message = ServerAuthMessage.create(
            AddressType.server, initiator.id, initiator.cookie_in,
            sign_keys=self._server.key is not None, responder_ids=responder_ids)
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
        """
        path, responder = self.path, self.client

        # Set key on client
        responder.set_client_key(message.client_public_key)

        # Receive client-auth
        message = yield from responder.receive()
        if message.type != MessageType.client_auth:
            error = "Expected 'client-auth', got '{}'"
            raise MessageFlowError(error.format(message.type))

        # Validate cookie and ensure no sub-protocol downgrade took place
        self._validate_cookie(message.server_cookie, responder.cookie_out)
        self._validate_subprotocol(message.subprotocols)

        # Authenticated
        id_ = path.add_responder(responder)

        # Send new-responder message if initiator is present
        initiator = path.get_initiator()
        initiator_connected = initiator is not None
        if initiator_connected:
            # Create message and add send coroutine to task queue of the initiator
            message = NewResponderMessage.create(AddressType.server, initiator.id, id_)
            initiator.log.debug('Enqueueing new-responder message')
            yield from initiator.enqueue_task(initiator.send(message))

        # Send server-auth
        message = ServerAuthMessage.create(
            AddressType.server, responder.id, responder.cookie_in,
            sign_keys=self._server.key is not None,
            initiator_connected=initiator_connected)
        responder.log.debug('Sending server-auth without responder ids')
        yield from responder.send(message)

    @asyncio.coroutine
    def task_loop(self):
        path, client = self.path, self.client
        while not client.connection_closed.done():
            # Get a task from the queue
            task = yield from client.dequeue_task()

            # Wait and catch exceptions, ignore cancelled tasks
            client.log.debug('Waiting for task to complete {}', task)
            try:
                yield from task
            except asyncio.CancelledError:
                client.log.debug('Task cancelled {}', task)

    @asyncio.coroutine
    def initiator_receive_loop(self):
        path, initiator = self.path, self.client
        while not initiator.connection_closed.done():
            # Receive relay message or drop-responder
            message = yield from initiator.receive()

            # Relay
            if isinstance(message, RawMessage):
                # Lookup responder
                responder = path.get_responder(message.destination)
                # Send to responder
                yield from self.relay_message(responder, message.destination, message)
            # Drop-responder
            elif message.type == MessageType.drop_responder:
                # Lookup responder
                responder = path.get_responder(message.responder_id)
                if responder is not None:
                    # Drop responder using its task queue
                    path.log.debug(
                        'Dropping responder {}, reason: {}', responder, message.reason)
                    responder.log.debug(
                        'Dropping (requested by initiator), reason: {}', message.reason)
                    coroutine = responder.close(code=message.reason.value)
                    yield from responder.enqueue_task(coroutine)
                else:
                    log_message = 'Responder {} already dropped, nothing to do'
                    path.log.debug(log_message, responder)
            else:
                error = "Expected relay message or 'drop-responder', got '{}'"
                raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def responder_receive_loop(self):
        path, responder = self.path, self.client
        while not responder.connection_closed.done():
            # Receive relay message
            message = yield from responder.receive()

            # Relay
            if isinstance(message, RawMessage):
                # Lookup initiator
                initiator = path.get_initiator()
                # Send to initiator
                yield from self.relay_message(initiator, AddressType.initiator, message)
            else:
                error = "Expected relay message, got '{}'"
                raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def relay_message(self, destination, destination_id, message):
        path, source = self.path, self.client

        # Prepare message
        source.log.debug('Packing relay message')
        message_id = message.pack(source)[16:]

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
        task = self._loop.create_task(destination.send(message))
        destination.log.debug('Enqueueing relayed message from 0x{:02x}', source.id)
        yield from destination.enqueue_task(task)

        # noinspection PyBroadException
        try:
            # Wait for send task to complete
            yield from asyncio.wait_for(task, RELAY_TIMEOUT, loop=self._loop)
        except asyncio.TimeoutError:
            # Timed out, send 'send-error' to source
            log_message = 'Sending relayed message to 0x{:02x} timed out'
            source.log.info(log_message, destination.id)
            yield from send_error_message()
        except Exception:
            # An exception has been triggered while sending the message.
            # Note: We don't care about the actual exception as the task
            #       will also trigger that exception on the destination
            #       client's handler who will log what happened.
            log_message = 'Sending relayed message failed, receiver 0x{:02x} is gone'
            source.log.info(log_message, destination.id)
            yield from send_error_message()

    @asyncio.coroutine
    def keep_alive_loop(self):
        """
        Disconnected
        PingTimeoutError
        """
        path, client = self.path, self.client
        while not client.connection_closed.done():
            # Wait
            yield from asyncio.sleep(client.keep_alive_interval, loop=self._loop)

            # Send ping and wait for pong
            client.log.debug('Ping')
            try:
                pong_future = yield from client.ping()
                yield from asyncio.wait_for(
                    pong_future, client.keep_alive_timeout, loop=self._loop)
            except asyncio.TimeoutError:
                raise PingTimeoutError(client)
            else:
                client.log.debug('Pong')

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
        chosen = self._select_subprotocol(
            client_subprotocols, self._server.subprotocols)
        if chosen != self.subprotocol.value:
            raise DowngradeError('Subprotocol downgrade detected')


class Paths:
    __slots__ = ('_log', 'number', 'paths')

    def __init__(self):
        self._log = util.get_logger('paths')
        self.number = 0
        self.paths = {}

    def get(self, initiator_key):
        if self.paths.get(initiator_key) is None:
            self.number += 1
            self.paths[initiator_key] = Path(initiator_key, self.number)
            self._log.debug('Created new path: {}', self.number)
        return self.paths[initiator_key]

    def clean(self, path):
        if path.empty:
            try:
                del self.paths[path.initiator_key]
            except KeyError:
                self._log.warning('Path {} has already been removed', path.number)
            else:
                self._log.debug('Removed empty path: {}', path.number)


class Server(asyncio.AbstractServer):
    subprotocols = [
        SubProtocol.saltyrtc_v1.value
    ]

    def __init__(self, key, paths, loop=None):
        self._log = util.get_logger('server')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # WebSocket server instance
        self._server = None

        # Store key and paths
        self.key = key
        self.paths = paths

        # Store server protocols
        self.protocols = set()

    @property
    def server(self):
        return self._server

    @server.setter
    def server(self, server):
        self._server = server
        self._log.debug('Server instance: {}', server)

    @asyncio.coroutine
    def handler(self, connection, ws_path):
        # Convert sub-protocol
        try:
            subprotocol = SubProtocol(connection.subprotocol)
        except ValueError:
            subprotocol = None

        # Determine ServerProtocol instance by selected sub-protocol
        if subprotocol != SubProtocol.saltyrtc_v1:
            self._log.notice("Unsupported sub-protocol '{}', dropping client",
                             connection.subprotocol)
            # We need to close the connection manually as the client may choose
            # to ignore
            yield from connection.close(code=CloseCode.subprotocol_error.value)
        else:
            protocol = ServerProtocol(self, subprotocol, loop=self._loop)
            protocol.connection_made(connection, ws_path)
            yield from protocol.handler_task

    def register(self, protocol):
        self.protocols.add(protocol)
        self._log.debug('Protocol registered: {}', protocol)

    def unregister(self, protocol):
        self.protocols.remove(protocol)
        self._log.debug('Protocol unregistered: {}', protocol)
        self.paths.clean(protocol.path)

    def close(self):
        """
        Close open connections and the server.
        """
        self._loop.create_task(self._close_after_all_protocols_closed())

    @asyncio.coroutine
    def wait_closed(self):
        """
        Wait until all connections are closed.
        """
        if len(self.protocols) > 0:
            tasks = [protocol.handler_task for protocol in self.protocols]
            yield from asyncio.wait(tasks, loop=self._loop)
        yield from self.server.wait_closed()

    @asyncio.coroutine
    def _close_after_all_protocols_closed(self, timeout=None):
        # Schedule closing all protocols
        self._log.debug('Closing protocols')
        if len(self.protocols) > 0:
            tasks = [protocol.close(code=CloseCode.going_away.value)
                     for protocol in self.protocols]

            # Wait until all protocols are closed (we need the server to be active for the
            # WebSocket close protocol)
            yield from asyncio.wait(tasks, loop=self._loop, timeout=timeout)

        # Now we can close the server
        self._log.debug('Closing server')
        self.server.close()
