"""
TODO: Describe tests
"""
import libnacl.public
import pytest
import websockets

from saltyrtc.server.typing import ListOrTuple


# noinspection PyStatementEffect
class TestTypes:
    def test_list_or_tuple_runtime(self):
        ListOrTuple[str]


@pytest.mark.usefixtures('evaluate_log')
class TestPrerequisites:
    @pytest.mark.asyncio
    async def test_server_handshake(self, ws_client_factory):
        """
        Make sure the server is reachable and we can do a simple
        WebSocket handshake using the correct sub-protocol.
        """
        client = await ws_client_factory()
        assert isinstance(client, websockets.client.WebSocketClientProtocol)
        assert client.subprotocol in pytest.saltyrtc.subprotocols
        await client.close()

    @pytest.mark.asyncio
    async def test_server_ping(self, ws_client_factory):
        """
        Make sure that we can *ping* the server and the server sends a
        *pong* response.
        """
        client = await ws_client_factory()
        pong = await client.ping()
        await pong
        await client.close()

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
