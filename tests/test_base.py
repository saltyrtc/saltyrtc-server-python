"""
TODO: Describe tests
"""
import pytest

import websockets


class TestPrerequisities:
    @pytest.mark.asyncio
    def test_server_handshake(self, ws_client_factory):
        """
        Make sure the server is reachable and we can do a simple
        WebSocket handshake using the correct sub-protocol.
        """
        client = yield from ws_client_factory()
        assert isinstance(client, websockets.client.WebSocketClientProtocol)
        assert client.subprotocol in pytest.saltyrtc.subprotocols
        yield from client.close()

    @pytest.mark.asyncio
    def test_server_ping(self, ws_client_factory):
        """
        Make sure that we can *ping* the server and the server sends a
        *pong* response.
        """
        client = yield from ws_client_factory()
        pong = yield from client.ping()
        yield from pong
        yield from client.close()
