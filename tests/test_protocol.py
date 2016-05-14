"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import asyncio

import pytest

import saltyrtc


class TestProtocol:
    @pytest.mark.asyncio
    def test_no_subprotocols(self, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = yield from ws_client_factory(subprotocols=None)
        yield from asyncio.sleep(0.05)
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.sub_protocol_error

    @pytest.mark.asyncio
    def test_invalid_subprotocols(self, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = yield from ws_client_factory(subprotocols=['kittie-protocol-3000'])
        yield from asyncio.sleep(0.05)
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.sub_protocol_error

    @pytest.mark.asyncio
    def test_server_hello(self, ws_client_factory, get_unencrypted_packet):
        """
        The server must send a valid `server-hello` on connection.
        """
        client = yield from ws_client_factory()
        receiver, message = yield from get_unencrypted_packet(client)
        assert receiver == 0x00
        assert message['type'] == 'server-hello'
        assert len(message['key']) == 32
        assert len(message['my-cookie']) == 16
        yield from client.close()
