"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import pytest

import saltyrtc


class TestProtocol:
    @pytest.mark.asyncio
    def test_no_subprotocols(self, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = yield from ws_client_factory(subprotocols=None)
        yield from sleep(0.05)
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.sub_protocol_error

    @pytest.mark.asyncio
    def test_invalid_subprotocols(self, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = yield from ws_client_factory(subprotocols=['kittie-protocol-3000'])
        yield from sleep(0.05)
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.sub_protocol_error

    @pytest.mark.asyncio
    def test_invalid_path(self, url, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = yield from ws_client_factory(path='{}/{}'.format(url, 'rawr!!!'))
        yield from sleep(0.05)
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_server_hello(self, client_factory):
        """
        The server must send a valid `server-hello` on connection.
        """
        client = yield from client_factory()
        receiver, message = yield from client.recv()
        assert receiver == 0x00
        assert message['type'] == 'server-hello'
        assert len(message['key']) == 32
        assert len(message['my-cookie']) == 16
        yield from client.ws_client.close()

    @pytest.mark.asyncio
    def test_invalid_client_hello(self, sleep, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        yield from client.send(0x00, {'type': 'meow-hello'})
        yield from sleep(0.05)
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error
