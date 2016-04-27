"""
TODO: Describe project
"""
import asyncio
import ssl

import websockets

from . import exception, util
from .util import get_logging_handler
from .exception import *

__author__ = 'Lennart Grahl <lennart.grahl@gmail.com>'
__status__ = 'Development'
__version__ = '0.0.1'
__all__ = (
    'serve',
    'logging_handler',
) + exception.__all__

# Create default logger and handler
logging_handler = util.get_logging_handler()
log = util.get_logger()


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
