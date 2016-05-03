"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import pytest


class TestProtocol:
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
