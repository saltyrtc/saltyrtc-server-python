import asyncio
import binascii

import websockets
import libnacl
import libnacl.public

from . import util
from .exception import *
from .common import (
    RELAY_TIMEOUT,
    KEEP_ALIVE_INTERVAL,
    KEEP_ALIVE_TIMEOUT,
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
def serve(ssl_context, paths=None, host=None, port=8765, loop=None):
    """
    Start serving SaltyRTC Signalling Clients.

    Arguments:
        - `ssl_context`: An `ssl.SSLContext` instance for WSS.
        - `paths`: A :class:`Paths` instance that maps path names to
          :class:`Path` instances. Can be used to share paths on
          multiple WebSockets. Defaults to an empty paths instance.
        - `host`: The hostname or IP address the server will listen on.
          Defaults to all interfaces.
        - `port`: The port the client should connect to. Defaults to
          `8765`.
        - `loop`: A :class:`asyncio.BaseEventLoop` instance.


    """
    if loop is None:
        loop = asyncio.get_event_loop()

    # Create paths if not given
    if paths is None:
        paths = Paths()

    # Create server
    server = Server(paths=paths, loop=loop)

    # Start server
    ws_server = yield from websockets.serve(
        server.handler,
        ssl=ssl_context,
        host=host,
        port=port,
        subprotocols=server.sub_protocols
    )

    # Set server instance
    server.server = ws_server

    # Return server
    return server


class ServerProtocol(Protocol):
    __slots__ = ('_log', '_loop', '_server', 'path', 'client', 'handler_task')

    def __init__(self, server, loop=None):
        self._log = util.get_logger('server.protocol')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # Server instance
        self._server = server

        # Path and client instance
        self.path = None
        self.client = None

        # Handler task that is set after 'connection_made' has been called
        self.handler_task = None

    def connection_made(self, connection, ws_path):
        self.handler_task = self._loop.create_task(self.handler(connection, ws_path))

    @asyncio.coroutine
    def close(self, code=1000):
        yield from self.client.close(code=code)

    @asyncio.coroutine
    def handler(self, connection, ws_path):
        self._log.debug('New connection on WS path {}', ws_path)

        # Get path and client instance as early as possible
        try:
            path, client = self.get_path_client(connection, ws_path)
        except PathError as exc:
            self._log.warning('Closing due to path error: {}', exc)
            yield from connection.close(code=CloseCode.protocol_error.value)
            return
        client.log.debug('Worker started')

        # Store path and client
        self.path = path
        self.client = client
        self._server.register(self)

        # Handle client until disconnected or an exception occurred
        try:
            yield from self.handle_client()
        except Disconnected:
            client.log.notice('Connection closed by remote')
        except SlotsFullError as exc:
            client.log.info('Closing because all path slots are full: {}', exc)
            yield from client.close(code=CloseCode.path_full_error.value)
        except SignalingError as exc:
            client.log.warning('Closing due to protocol error: {}', exc)
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
        client = PathClient(connection, path.number, initiator_key)

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
        """
        path, client = self.path, self.client

        # Do handshake
        client.log.debug('Starting handshake')
        yield from self.handshake()
        client.log.debug('Handshake completed')

        # Task: Execute enqueued tasks
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
        tasks.append(self.keep_alive())

        # Wait until complete
        tasks = [self._loop.create_task(coroutine) for coroutine in tasks]
        done, pending = yield from asyncio.wait(
            tasks, loop=self._loop, return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            exc = task.exception()
            if exc is not None:
                # Cancel pending tasks
                for pending_task in pending:
                    client.log.debug('Cancelling task {}', pending_task)
                    pending_task.cancel()
                raise exc
            else:
                client.log.error('Task {} returned unexpectedly', task)
                raise SignalingError('Task returned too early')

    @asyncio.coroutine
    def handshake(self):
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        """
        path, client = self.path, self.client

        # Send server-hello
        message = ServerHelloMessage.create(0x00, client.id, client.server_key.pk)
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
        """
        path, initiator = self.path, self.client

        # Validate cookie
        self._validate_cookie(message.server_cookie, initiator.cookie_out)

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
            message = NewInitiatorMessage.create(0x00, responder_id)
            responder.log.debug('Enqueueing new-initiator message')
            yield from responder.enqueue_task(responder.send(message))

        # Send server-auth
        responder_ids = path.get_responder_ids()
        message = ServerAuthMessage.create(
            0x00, initiator.id, initiator.cookie_in, responder_ids=responder_ids)
        initiator.log.debug('Sending server-auth including responder ids')
        yield from initiator.send(message)

    @asyncio.coroutine
    def handshake_responder(self, message):
        """
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        """
        path, responder = self.path, self.client

        # Set key on client
        responder.set_client_key(message.client_public_key)

        # Receive client-auth
        message = yield from responder.receive()
        if message.type != MessageType.client_auth:
            error = "Expected 'client-auth', got '{}'"
            raise MessageFlowError(error.format(message.type))

        # Validate cookie
        self._validate_cookie(message.server_cookie, responder.cookie_out)

        # Authenticated
        id_ = path.add_responder(responder)

        # Send new-responder message if initiator is present
        initiator = path.get_initiator()
        initiator_connected = initiator is not None
        if initiator_connected:
            # Create message and add send coroutine to task queue of the initiator
            message = NewResponderMessage.create(0x00, initiator.id, id_)
            initiator.log.debug('Enqueueing new-responder message')
            yield from initiator.enqueue_task(initiator.send(message))

        # Send server-auth
        message = ServerAuthMessage.create(
            0x00, responder.id, responder.cookie_in,
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
                yield from self.relay_message(responder, message)
            # Drop-responder
            elif message.type == MessageType.drop_responder:
                # Lookup responder
                responder = path.get_responder(message.responder_id)
                if responder is not None:
                    # Drop responder using its task queue
                    path.log.debug('Dropping responder {}', responder)
                    responder.log.debug('Dropping (requested by initiator)')
                    coroutine = responder.close(code=CloseCode.drop_by_initiator.value)
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
                yield from self.relay_message(initiator, message)
            else:
                error = "Expected relay message, got '{}'"
                raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def relay_message(self, destination, message):
        path, source = self.path, self.client

        # Prepare message
        source.log.debug('Packing relay message')
        message_data = message.pack(source)

        @asyncio.coroutine
        def send_error_message():
            # Create message and add send coroutine to task queue of the source
            error = SendErrorMessage.create(
                0x00, source.id, libnacl.crypto_hash_sha256(message_data))
            source.log.debug('Relaying failed, enqueuing send-error')
            yield from source.enqueue_task(source.send(error))

        # Destination not connected? Send 'send-error' to source
        if destination is None:
            error_message = ('Cannot relay message, no connection for '
                             'destination id 0x{:02x}')
            source.log.notice(error_message, destination.id)
            yield from send_error_message()
            return

        # Add send task to task queue of the source
        task = self._loop.create_task(destination.send(message))
        destination.log.debug('Enqueueing relayed message from 0x{:x}', source.id)
        yield from destination.enqueue_task(task)

        # noinspection PyBroadException
        try:
            # Wait for send task to complete
            yield from asyncio.wait_for(task, RELAY_TIMEOUT, loop=self._loop)
        except asyncio.TimeoutError:
            # Timed out, send 'send-error' to source
            log_message = 'Sending relayed message to 0x{:x} timed out'
            source.log.debug(log_message, destination.id)
            yield from send_error_message()
        except Exception:
            # An exception has been triggered while sending the message.
            # Note: We don't care about the actual exception as the task
            #       will also trigger that exception on the destination
            #       client's handler who will log what happened.
            log_message = 'Sending relayed message failed, receiver 0x{:x} is gone'
            source.log.debug(log_message, destination.id)
            yield from send_error_message()

    @asyncio.coroutine
    def keep_alive(self):
        """
        Disconnected
        PingTimeoutError
        """
        path, client = self.path, self.client

        while True:
            # Wait
            yield from asyncio.sleep(KEEP_ALIVE_INTERVAL, loop=self._loop)

            # Send ping and wait for pong
            client.log.debug('Ping')
            try:
                pong_future = yield from asyncio.wait_for(
                    client.ping(), KEEP_ALIVE_TIMEOUT, loop=self._loop)
                yield from asyncio.wait_for(
                    pong_future, KEEP_ALIVE_TIMEOUT, loop=self._loop)
            except asyncio.TimeoutError:
                raise PingTimeoutError(client)
            else:
                client.log.debug('Pong')

    def _validate_cookie(self, expected_cookie, actual_cookie):
        self.client.log.debug('Validating cookie')
        if not util.consteq(expected_cookie, actual_cookie):
            raise MessageError('Cookies do not match')


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
    sub_protocols = [
        SubProtocol.saltyrtc_v1_0.value
    ]

    def __init__(self, paths, loop=None):
        self._log = util.get_logger('server')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # WebSocket server instance
        self._server = None

        # Store paths
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
        if subprotocol != SubProtocol.saltyrtc_v1_0:
            self._log.notice("Unsupported sub-protocol '{}', dropping client",
                             connection.subprotocol)
            # We need to close the connection manually as the client may choose
            # to ignore
            yield from connection.close(code=CloseCode.sub_protocol_error.value)
        else:
            protocol = ServerProtocol(self, loop=self._loop)
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
        self._log.debug('Closing protocols')
        for protocol in self.protocols:
            self._loop.create_task(protocol.close(code=CloseCode.going_away.value))
        self._log.debug('Closing server')
        self.server.close()

    @asyncio.coroutine
    def wait_closed(self):
        """
        Wait until all connections are closed.
        """
        if len(self.protocols) > 0:
            tasks = [protocol.handler_task for protocol in self.protocols]
            yield from asyncio.wait(tasks, loop=self._loop)
        yield from self.server.wait_closed()
