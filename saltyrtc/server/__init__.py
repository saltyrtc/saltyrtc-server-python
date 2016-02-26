"""
TODO: Describe project
"""
import json
import asyncio
import enum
import ssl

import websockets

from . import config
from ._asyncio import gather

from . import exception, util
from .util import get_logging_handler
from .exception import *

__author__ = 'Lennart Grahl <lennart.grahl@threema.ch>'
__status__ = 'Development'
__version__ = '0.0.1'
__all__ = (
    'serve',
    'logging_handler',
) + exception.__all__

# Create default logger and handler
logging_handler = util.get_logging_handler()
log = util.get_logger()

# Globals
paths = {}


@enum.unique
class Role(enum.Enum):
    client = 1
    server = 2

    @staticmethod
    def opposite(role):
        if role == Role.client:
            return Role.server
        elif role == Role.server:
            return Role.client
        else:
            raise RoleError(role)


class Path(object):
    __slots__ = 'hash', 'logger', 'key', '_client', '_server'

    def __init__(self):
        self.hash = hex(id(self))
        self.logger = util.get_logger(self.hash)
        self.key = None
        self._client = asyncio.Future()
        self._server = asyncio.Future()

    def __str__(self):
        return self.hash

    def get(self, role):
        if role == Role.client:
            future = self._client
        elif role == Role.server:
            future = self._server
        else:
            raise RoleError(role)

        # The future is shielded from cancellation errors
        return asyncio.shield(future)

    def set(self, ws, role, key=None):
        try:
            # Get currently registered connection
            registered_ws = self.get(role).result()
        except asyncio.InvalidStateError:
            # There is no connection registered
            pass
        else:
            # Un-register and close currently registered connection
            self.logger.debug('{} overwrite registered connection', role)
            asyncio.async(registered_ws.close())
            self.remove(role)

        # Set connection for role
        if role == Role.server and key is None:
            raise ValueError('Server role requires a key')
        if role == Role.client:
            self._client.set_result(ws)
        elif role == Role.server:
            self._server.set_result(ws)
            self.key = key
        else:
            raise RoleError(role)

    def remove(self, role):
        if role == Role.client:
            self._client = asyncio.Future()
        elif role == Role.server:
            self._server = asyncio.Future()
            self.key = None
        else:
            raise RoleError(role)

    def disconnect(self, ws, role, exc=None):
        try:
            # Get currently registered connection
            registered_ws = self.get(role).result()
        except asyncio.InvalidStateError:
            # There is no connection registered
            pass
        else:
            # Check if this connection is the currently registered connection
            if registered_ws == ws:
                # Remove it from the path
                self.remove(role)
                self.logger.debug('{} unregistered', role)

        # Close connection
        asyncio.async(ws.close())
        if exc is not None:
            self.logger.info('{} dropped because of exception', role)
            self.logger.error(exc)
        else:
            self.logger.info('{} disconnected', role)

    @asyncio.coroutine
    def other(self, my_ws, role):
        # Get other connection
        other_ws = yield from self.get(Role.opposite(role))
        # Check my connection
        if not my_ws.open:
            raise Disconnected()
        return other_ws

    @asyncio.coroutine
    def register(self, ws):
        self.logger.debug('Waiting for register message...')

        # Get message
        try:
            message = yield from ws.recv()
        except websockets.ConnectionClosed as exc:
            raise Disconnected() from exc

        # Check for disconnect
        if message is None:
            raise MessageFlowError('Disconnected while registering')

        # Check instance type
        if not isinstance(message, str):
            raise MessageFlowError('Sent non-string message while registering')

        # Check JSON
        try:
            data = json.loads(message)
        except ValueError as exc:
            raise MessageFlowError('Sent invalid JSON object while registering') from exc

        # Check type
        type_ = data.get(config.field_type)
        if type_ == config.type_hello_server:
            # Check for key
            key = data.get(config.type_key)
            if key is not None:
                # Register connection and set key
                role = Role.server
                self.set(ws, role, key=key)
            else:
                raise MessageFlowError('Registered as server but key is missing')
        elif type_ == config.type_hello_client:
            # Register connection
            role = Role.client
            self.set(ws, role)
        else:
            raise MessageFlowError('Unknown register type <{}>'.format(type_))

        # Return role
        self.logger.info('{} registered', role)
        return role

    @asyncio.coroutine
    def send_key(self, ws):
        role = Role.client

        # Wait for other connection
        yield from self.other(ws, role)

        # Make sure the key exists
        if self.key is None:
            raise MessageFlowError('Key not present while trying to send key')

        # Create key message
        message = {
            config.field_type: config.type_key,
            config.field_data: self.key
        }

        # Send key message
        self.logger.info('Sending key to {}', role)
        try:
            yield from ws.send(json.dumps(message))
        except websockets.InvalidState as exc:
            self.logger.warning("{} couldn't send key, disconnected", role)
            self.logger.error(exc)

    @asyncio.coroutine
    def send_reset(self, ws, role, message):
        sent = False
        # Relentlessly send reset until the other connection received it
        while not sent:
            sent = yield from self.send(ws, role, message, send_error_message=False)

    @asyncio.coroutine
    def send(self, my_ws, role, message, send_error_message=True):
        # Wait for other connection
        other_ws = yield from self.other(my_ws, role)

        # Send message
        self.logger.info('{} sending message...', role)
        try:
            yield from other_ws.send(message)
            self.logger.info('{} ... message sent', role)
            return True
        except websockets.InvalidState as exc:
            self.logger.error(exc)
            self.logger.info('{} sending failed, other is disconnected', role)
            if send_error_message:
                yield from self.send_error(my_ws, role)
            return False

    @asyncio.coroutine
    def receive(self, ws, role):
        # Receive message
        self.logger.info('{} receiving message...', role)
        message = yield from ws.recv()
        if message is None:
            raise Disconnected()
        else:
            self.logger.info('{} ... message received', role)
            if isinstance(message, str):
                # Handle non-binary message and wait for another message
                yield from self.handle(ws, role, message)
                message = yield from self.receive(ws, role)
            return message

    @asyncio.coroutine
    def handle(self, ws, role, message):
        # Check JSON
        try:
            data = json.loads(message)
        except ValueError as exc:
            error = '{}: {} sent invalid JSON object in non-binary message'.format(
                self, role)
            raise MessageFlowError(error) from exc

        # Check type
        type_ = data.get(config.field_type)
        if type_ == config.type_reset:
            # Dispatch silently
            yield from self.send_reset(ws, role, message)
        else:
            error = '{}: {} sent unknown non-binary message type <{}>'.format(
                self, role, type_)
            raise MessageFlowError(error)

    @asyncio.coroutine
    def send_error(self, ws, role):
        # Create error message
        message = {config.field_type: config.type_send_error}

        # Send error message
        self.logger.info('Sending send error notification to {}', role)
        try:
            yield from ws.send(json.dumps(message))
        except websockets.InvalidState as exc:
            self.logger.warning("{} couldn't send error message, disconnected", role)
            self.logger.error(exc)


@asyncio.coroutine
def channel(ws, path, role):
    try:
        # Send key if client
        # Note: We deliberately dispatch the key ONCE, so the key can't be changed
        #       unless the client reconnects (e.g. pressing F5 in the browser)
        if role == Role.client:
            yield from path.send_key(ws)

        # Dispatch messages until disconnect
        while True:
            # Get message
            message = yield from path.receive(ws, role)

            # Disconnect?
            if message is None:
                raise Disconnected()

            # Dispatch message
            yield from path.send(ws, role, message)
    except asyncio.CancelledError:
        path.logger.debug('Cancelled {}', role)


@asyncio.coroutine
def keep_alive(logger, ws, role):
    try:
        while True:
            # Check connection
            if not ws.open:
                raise Disconnected()

            logger.debug('Ping to {}', role)
            try:
                # Send ping
                yield from asyncio.wait_for(ws.ping(), config.ping_timeout)
            except asyncio.TimeoutError:
                raise PingTimeoutError(role)
            else:
                logger.debug('Pong from {}', role)

            # Wait
            yield from asyncio.sleep(config.ping_interval)
    except asyncio.CancelledError:
        logger.debug('Ping cancelled {}', role)


@asyncio.coroutine
def signaling(ws, path):
    # Extract public key from path
    path = path.strip('/')

    try:
        # Validate path
        if len(path) != config.path_length:
            raise PathError(len(path))
    except PathError as exc:
        util.get_logger().error(exc)
        return

    # Create path instance (if necessary)
    global paths
    paths.setdefault(path, Path())
    path = paths[path]
    path.logger.info('New connection')

    try:
        # Register connection and retrieve role
        role = yield from path.register(ws)
    except SignalingError as exc:
        path.logger.error(exc)
        return
    except Disconnected:
        # Disconnect normally
        return

    # Setup tasks
    tasks = gather(
        keep_alive(path.logger, ws, role),
        channel(ws, path, role),
        exceptions_cancel_tasks=True
    )
    try:
        # Startup channel for both peers and keep the connection alive
        # Stop when one of the tasks raises an exception or returns
        # Note: Only the channel can return
        yield from tasks
    except SignalingError as exc:
        # Disconnect with an error
        path.disconnect(ws, role, exc=exc)
    except Disconnected:
        # Disconnect normally
        path.disconnect(ws, role)
    else:
        path.logger.warning('Unreachable section')


@asyncio.coroutine
def serve(certfile, keyfile=None, host=None, port=8765, loop=None):
    """
    Start serving SaltyRTC Signalling Clients.

    Arguments:
        - `certfile`: Path to a file in PEM format containing the
          SSL certificate of the server.
        - `keyfile`: Path to a file that contains the private key.
          Will be read from `certfile` if not present.
        - `ssl`: An `ssl.SSLContext` instance for WSS.
        - `host`: The hostname or IP address the server will listen on.
          Defaults to all interfaces.
        - `port`: The port the client should connect to. Defaults to
          `8765`.
        - `loop`: A :class:`asyncio.BaseEventLoop` instance.
    """
    # Get loop
    loop = loop if loop is not None else asyncio.get_event_loop()
    log.debug('Event loop: {}', loop)

    # Create SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    log.debug('Created SSL context', ssl_context)

    # Start server
    log.debug('Starting server')
    server = yield from websockets.serve(
        signaling, ssl=ssl_context, host=host, port=port)

    # Return server
    log.notice('Listening')
    return server
