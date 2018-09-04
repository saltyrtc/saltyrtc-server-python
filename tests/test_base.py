"""
TODO: Describe tests
"""
import libnacl.public
import pytest
import websockets


@pytest.mark.usefixtures('evaluate_log')
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

    def test_packet_min_length(self):
        """
        Check that an empty NaCl message takes exactly 40 bytes (24
        bytes nonce and 16 bytes NaCl authenticator).
        """
        a = libnacl.public.SecretKey()
        b = libnacl.public.SecretKey()
        box = libnacl.public.Box(sk=a.sk, pk=b.pk)
        nonce, data = box.encrypt(b'', pack_nonce=False)
        assert len(nonce) == 24
        assert len(data) == 16
