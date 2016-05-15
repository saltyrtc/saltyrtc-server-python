"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import struct

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
        receiver, message, _ = yield from client.recv()
        assert receiver == 0x00
        assert message['type'] == 'server-hello'
        assert len(message['key']) == 32
        assert len(message['my-cookie']) == 16
        yield from client.ws_client.close()

    @pytest.mark.asyncio
    def test_invalid_message_type(self, sleep, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        yield from client.send(0x00, {'type': 'meow-hello'})
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
        yield from client.send(0x00, {'type': 'client-hello'})
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
        yield from client.send(0x00, {
            'type': 'client-hello',
            'key': b'meow?'
        })
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_duplicated_cookie(self, sleep, initiator_key, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        _, message, _ = yield from client.recv()
        cookie = message['my-cookie']
        cn, csn, ssn = 0, 0, 0
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        yield from client.send(0x00, {
            'type': 'client-auth',
            'your-cookie': cookie,
            'my-cookie': cookie
        }, nonce=cookie + struct.pack('!2I', cn, csn))
        csn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_initiator_handshake(self, cookie, initiator_key, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        _, message, _ = yield from client.recv()
        server_cookie = message['my-cookie']
        cn, csn, ssn = 0, 0, 0
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        yield from client.send(0x00, {
            'type': 'client-auth',
            'your-cookie': server_cookie,
            'my-cookie': cookie
        }, nonce=cookie + struct.pack('!2I', cn, csn))
        csn += 1

        # server-auth
        _, message, nonce = yield from client.recv()
        assert nonce == server_cookie + struct.pack('!2I', cn, ssn)
        assert message['type'] == 'server-auth'
        assert message['your-cookie'] == cookie
        assert 'initiator-connected' not in message
        assert len(message['responders']) == 0
        ssn += 1

    @pytest.mark.asyncio
    def test_responder_handshake(self, cookie, responder_key, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        _, message, _ = yield from client.recv()
        server_cookie = message['my-cookie']

        # client-hello
        yield from client.send(0x00, {
            'type': 'client-hello',
            'key': responder_key.pk,
        })

        cn, csn, ssn = 0, 0, 0
        client.box = libnacl.public.Box(sk=responder_key, pk=message['key'])

        # client-auth
        yield from client.send(0x00, {
            'type': 'client-auth',
            'your-cookie': server_cookie,
            'my-cookie': cookie
        }, nonce=cookie + struct.pack('!2I', cn, csn))
        csn += 1

        # server-auth
        _, message, nonce = yield from client.recv()
        assert nonce == server_cookie + struct.pack('!2I', cn, ssn)
        assert message['type'] == 'server-auth'
        assert message['your-cookie'] == cookie
        assert not message['initiator-connected']
        ssn += 1

