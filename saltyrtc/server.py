import asyncio
import binascii
import os

import websockets
import libnacl
import libnacl.public

from . import util
from .exception import *
from .common import (
    KEY_LENGTH,
    COOKIE_LENGTH,
    RELAY_TIMEOUT,
    KEEP_ALIVE_INTERVAL,
    KEEP_ALIVE_TIMEOUT,
    CloseCode,
    ReceiverType,
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
    NewResponderMessage,
    SendErrorMessage,
    RawMessage,
)

__all__ = (
    'serve',
    'Server',
)

_server_log = util.get_logger('server')


@asyncio.coroutine
def serve(ssl_context, paths=None, host=None, port=8765, loop=None):
    """
    Start serving SaltyRTC Signalling Clients.

    Arguments:
        - `ssl_context`: An `ssl.SSLContext` instance for WSS.
        - `paths`: A dictionary that maps path names to :class:`Path`
          instances. Can be used to share paths on multiple WebSockets.
          Defaults to an empty dictionary.
        - `host`: The hostname or IP address the server will listen on.
          Defaults to all interfaces.
        - `port`: The port the client should connect to. Defaults to
          `8765`.
        - `loop`: A :class:`asyncio.BaseEventLoop` instance.


    """
    if loop is None:
        loop = asyncio.get_event_loop()

    # Create server
    server = Server(paths=paths, loop=loop)

    # Start server and set WS instance on server
    _server_log.debug('Starting WebSockets server')
    ws_server = yield from websockets.serve(
        server.serve_client,
        ssl=ssl_context,
        host=host,
        port=port
    )
    server.ws_server = ws_server
    _server_log.notice('Listening')

    # Return server
    return server


# TODO: Extract common methods of server and client into Protocol class
# TODO: Remember create_task tasks and clean up when closing
class Server(Protocol):
    PATH_LENGTH = KEY_LENGTH * 2

    def __init__(self, paths=None, loop=None):
        self._log = util.get_logger('server.protocol')
        self._loop = asyncio.get_event_loop() if loop is None else loop

        # WebSocket server instance
        self.ws_server = None

        # Paths dict
        self._path_number = 0
        self._paths = {} if paths is None else paths

        # Set to None when closing
        self._closing_future = asyncio.Future(loop=self._loop)
        # Set to None when closed
        self._closed_future = asyncio.Future(loop=self._loop)

    @asyncio.coroutine
    def wait_closed(self):
        yield from asyncio.shield(self._closed_future, loop=self._loop)

    def close(self, timeout=3.0):
        if self._closing_future.done() or self._closed_future.done():
            return

        # Set closing future
        self._log.info('Closing')
        self._closing_future.set_result(None)

        # Clean up task
        self._loop.create_task(self._clean_up(timeout))

    @asyncio.coroutine
    def _clean_up(self, timeout):
        # TODO: Wait for pending tasks to return or cancel them after a timeout
        # yield from asyncio.sleep(timeout, loop=self._loop)

        # Wait until WebSockets server is closed
        self.ws_server.close()
        yield from self.ws_server.wait_closed()

        # Set closed
        self._log.info('Closed')
        self._closed_future.set_result(None)

    @asyncio.coroutine
    def serve_client(self, connection, ws_path):
        self._log.debug('New connection on WS path {}', ws_path)

        # Get path and client instance as early as possible
        try:
            path, client = self._get_path_client(connection, ws_path)
        except PathError:
            yield from connection.close(code=CloseCode.protocol_error.value)
            return
        path.log.debug('Worker started')

        # Handle client until disconnected or an exception occurred
        try:
            yield from self._handle_client(path, client)
        except Disconnected:
            path.log.notice('Connection closed by remote')
        except SlotsFullError as exc:
            path.log.info('Closing because all path slots are full: {}', str(exc))
            yield from client.close(code=CloseCode.path_full_error.value)
        except SignalingError as exc:
            path.log.warning('Closing due to protocol error: {}', str(exc))
            yield from client.close(code=CloseCode.protocol_error.value)
        except Exception as exc:
            path.log.exception('Closing due to exception:', exc)
            yield from client.close(code=CloseCode.internal_error.value)
        path.log.debug('Worker stopped')

    def _get_path_client(self, connection, ws_path):
        # Extract public key from path
        initiator_key = ws_path.strip('/')

        # Validate key
        if len(initiator_key) != self.PATH_LENGTH:
            raise PathError('Invalid path length: {}'.format(len(initiator_key)))
        try:
            initiator_key = binascii.unhexlify(initiator_key)
        except binascii.Error as exc:
            raise PathError('Could not unhexlify path') from exc

        # Get path instance
        path = self._get_path(initiator_key)

        # Create client instance
        client = PathClient(connection, path.number, initiator_key)

        # Return path and client
        return path, client

    @asyncio.coroutine
    def _handle_client(self, path, client):
        """
        SignalingError
        PathError
        Disconnected
        MessageError
        MessageFlowError
        SlotsFullError
        """
        # Do handshake
        path.log.debug('Starting handshake')
        yield from self._handshake(path, client)
        path.log.debug('Handshake completed')

        # Keep alive and poll for messages
        tasks = []
        if client.type == ReceiverType.initiator:
            path.log.debug('Starting runner for initiator {}', client)
            tasks.append(self._handle_initiator(path, client))
        elif client.type == ReceiverType.responder:
            path.log.debug('Starting runner for responder {}', client)
            tasks.append(self._handle_responder(path, client))
        else:
            raise ValueError('Invalid receiver type: {}'.format(client.type))
        path.log.debug('Starting keep-alive task for client {}', client)
        tasks.append(self._keep_alive(path, client))

        # Wait until complete
        tasks = [self._loop.create_task(coroutine) for coroutine in tasks]
        done, pending = yield from asyncio.wait(
            tasks, loop=self._loop, return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            exc = task.exception()
            if exc is not None:
                # Cancel pending tasks
                for pending_task in pending:
                    path.log.debug('Cancelling task {}', task)
                    pending_task.cancel()
                raise exc
            else:
                path.log.error('Task {} returned unexpectedly', task)
                raise SignalingError('Task returned too early')

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

    @asyncio.coroutine
    def _keep_alive(self, path, client):
        """
        Disconnected
        PingTimeoutError
        """
        while True:
            path.log.debug('Ping to {}', client)
            try:
                # Send ping
                yield from asyncio.wait_for(
                    client.ping(), KEEP_ALIVE_TIMEOUT, loop=self._loop)
            except asyncio.TimeoutError:
                raise PingTimeoutError(client)
            else:
                path.log.debug('Pong from {}', client)

            # Wait
            yield from asyncio.sleep(KEEP_ALIVE_INTERVAL, loop=self._loop)

    @asyncio.coroutine
    def _handle_initiator(self, path, initiator):
        while not self._closing_future.done():
            # Receive relay message or drop-responder
            message = yield from initiator.receive()

            # Relay
            if isinstance(message, RawMessage):
                # Lookup responder
                responder = path.get_responder(message.receiver)
                # Send to responder
                coroutine = self._relay_message(path, initiator, responder, message)
                self._loop.create_task(coroutine)
            # Drop-responder
            elif message.type == MessageType.drop_responder:
                # Lookup responder
                responder = path.get_responder(message.responder_id)
                if responder is not None:
                    # Drop previous initiator (we don't care about any exceptions)
                    path.log.debug('Dropping responder: {}', responder)
                    self._loop.create_task(responder.close())
                else:
                    path.log.debug('Responder already dropped, nothing to do')
            else:
                error = "Expected relay message or 'drop-responder', got '{}'"
                raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def _handle_responder(self, path, responder):
        while not self._closing_future.done():
            # Receive relay message
            message = yield from responder.receive()

            # Relay
            if isinstance(message, RawMessage):
                # Lookup initiator
                initiator = path.get_initiator()
                # Send to initiator
                coroutine = self._relay_message(path, responder, initiator, message)
                self._loop.create_task(coroutine)
            else:
                error = "Expected relay message, got '{}'"
                raise MessageFlowError(error.format(message.type))

    @asyncio.coroutine
    def _relay_message(self, path, sender, receiver, message):
        # Prepare message
        path.log.debug('Packing relay message')
        message_data = message.pack(sender)

        @asyncio.coroutine
        def send_error_message():
            path.log.debug('Relaying failed, reporting send-error to {}', sender)
            error = SendErrorMessage.create(libnacl.crypto_hash_sha256(message_data))
            # TODO: Handle exceptions, what if sender is gone?
            yield from sender.send(error)

        # Receiver not set? Send send-error to initiator
        if receiver is None:
            return (yield from send_error_message())

        path.log.debug('Sending relay message from {} to {}', sender, receiver)
        try:
            # Relay message to receiver
            future = receiver.send(message)
            yield from asyncio.wait_for(future, RELAY_TIMEOUT, loop=self._loop)
        except asyncio.TimeoutError:
            # Timed out or some other error, Send send-error to original sender
            path.log.debug('Sending relayed message timed out')
            yield from send_error_message()
        except Disconnected:
            path.log.debug('Receiver disconnected')
            yield from send_error_message()

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
