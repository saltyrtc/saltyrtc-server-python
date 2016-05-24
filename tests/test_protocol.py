"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import pytest
import libnacl.public

import saltyrtc


class TestProtocol:
    @pytest.mark.asyncio
    def test_no_subprotocols(self, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = yield from ws_client_factory(subprotocols=None)
        yield from sleep()
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.sub_protocol_error

    @pytest.mark.asyncio
    def test_invalid_subprotocols(self, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = yield from ws_client_factory(subprotocols=['kittie-protocol-3000'])
        yield from sleep()
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.sub_protocol_error

    @pytest.mark.asyncio
    def test_invalid_path(self, url, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = yield from ws_client_factory(path='{}/{}'.format(url, 'rawr!!!'))
        yield from sleep()
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_server_hello(self, client_factory):
        """
        The server must send a valid `server-hello` on connection.
        """
        client = yield from client_factory()
        message, _, sck, s, d, scf, ssn = yield from client.recv()
        assert s == d == 0x00
        assert ssn == 0
        assert message['type'] == 'server-hello'
        assert len(message['key']) == 32
        yield from client.ws_client.close()

    @pytest.mark.asyncio
    def test_invalid_message_type(self, sleep, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        yield from client.send(b'\x00' * 24, {'type': 'meow-hello'})
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_field_missing(self, sleep, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        yield from client.send(b'\x00' * 24, {'type': 'client-hello'})
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_field(self, sleep, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        yield from client.send(b'\x00' * 24, {
            'type': 'client-hello',
            'key': b'meow?'
        })
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_duplicated_cookie(self, sleep, initiator_key, pack_nonce, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, scf, ssn = yield from client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccf, csn = sck, b'\x11\x11', 0
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccf, csn), {
            'type': 'client-auth',
            'your_cookie': sck,
        })
        csn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_initiator_handshake(self, cookie, initiator_key, pack_nonce, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, scf, ssn = yield from client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccf, csn = cookie, b'\x11\x11', 0
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccf, csn), {
            'type': 'client-auth',
            'your_cookie': sck,
        })
        csn += 1

        # server-auth
        message, _, ck, s, d, cf, ssn = yield from client.recv()
        assert s == 0x00
        assert d == 0x01
        assert sck == ck
        assert scf == cf
        assert ssn == 1
        assert message['type'] == 'server-auth'
        assert message['your_cookie'] == cck
        assert 'initiator_connected' not in message
        assert len(message['responders']) == 0

        yield from client.close()

    @pytest.mark.asyncio
    def test_responder_handshake(self, cookie, responder_key, pack_nonce, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, scf, ssn = yield from client.recv()

        # client-hello
        cck, ccf, csn = cookie, b'\x11\x11', 0
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccf, csn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        csn += 1

        # client-auth
        client.box = libnacl.public.Box(sk=responder_key, pk=message['key'])
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccf, csn), {
            'type': 'client-auth',
            'your_cookie': sck,
        })
        csn += 1

        # server-auth
        message, _, ck, s, d, cf, ssn = yield from client.recv()
        assert s == 0x00
        assert 0x01 < d <= 0xff
        assert sck == ck
        assert scf == cf
        assert ssn == 1
        assert message['type'] == 'server-auth'
        assert message['your_cookie'] == cck
        assert 'responders' not in message
        assert not message['initiator_connected']

        yield from client.close()
