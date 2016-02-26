"""
TODO: Describe tests
"""
import pytest

import websockets


class TestPrerequisities:
    @pytest.mark.asyncio
    def test_server_handshake(self, client_factory):
        """
        Make sure the server is reachable and we can do a simple
        WebSocket handshake.
        """
        client = yield from client_factory()
        assert isinstance(client, websockets.client.WebSocketClientProtocol)
        yield from client.close()

    @pytest.mark.asyncio
    def test_server_ping(self, client_factory):
        """
        Make sure that we can ping the server.
        """
        client = yield from client_factory()
        yield from client.ping()
        yield from client.close()
