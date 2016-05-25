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
    def test_invalid_path_length(self, url, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = yield from ws_client_factory(path='{}/{}'.format(url, 'rawr!!!'))
        yield from sleep()
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_path_symbols(self, url, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = yield from ws_client_factory(path='{}/{}'.format(url, 'äöüä' * 16))
        yield from sleep()
        assert not client.open
        assert client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_server_hello(self, client_factory):
        """
        The server must send a valid `server-hello` on connection.
        """
        client = yield from client_factory()
        message, _, sck, s, d, scsn = yield from client.recv()
        assert s == d == 0x00
        assert scsn & 0xffff00000000 == 0
        assert message['type'] == 'server-hello'
        assert len(message['key']) == 32
        yield from client.ws_client.close()

    @pytest.mark.asyncio
    def test_invalid_message_type(self, sleep, cookie, pack_nonce, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        cck, ccsn = cookie, 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'meow-hello'
        })
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_field_missing(self, sleep, cookie, pack_nonce, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        cck, ccsn = cookie, 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello'
        })
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_field(self, sleep, cookie, pack_nonce, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        cck, ccsn = cookie, 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
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
        message, _, sck, s, d, scsn = yield from client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccsn = sck, 2**32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_initiator_invalid_source(self, sleep, cookie, initiator_key, pack_nonce,
                                      client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()

        # client-hello
        cck, ccsn = cookie, 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x01, 0x00, ccsn), {
            'type': 'client-hello',
            'key': initiator_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_responder_invalid_source(self, sleep, cookie, responder_key, pack_nonce,
                                      client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()

        # client-hello
        cck, ccsn = cookie, 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0xff, 0x00, ccsn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_destination(self, sleep, cookie, initiator_key, pack_nonce,
                                 client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()

        # client-hello
        cck, ccsn = cookie, 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0xff, ccsn), {
            'type': 'client-hello',
            'key': initiator_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_initiator_handshake(self, cookie, initiator_key, pack_nonce, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccsn = cookie, 2**32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
        })
        ccsn += 1

        # server-auth
        message, _, ck, s, d, scsn = yield from client.recv()
        assert s == 0x00
        assert d == 0x01
        assert sck == ck
        assert scsn == start_scsn + 1
        assert message['type'] == 'server-auth'
        assert message['your_cookie'] == cck
        assert 'initiator_connected' not in message
        assert len(message['responders']) == 0

        yield from client.close()

    @pytest.mark.asyncio
    def test_responder_handshake(self, cookie, responder_key, pack_nonce, client_factory):
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()

        # client-hello
        cck, ccsn = cookie, 2**32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        ccsn += 1

        # client-auth
        client.box = libnacl.public.Box(sk=responder_key, pk=message['key'])
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
        })
        ccsn += 1

        # server-auth
        message, _, ck, s, d, scsn = yield from client.recv()
        assert s == 0x00
        assert 0x01 < d <= 0xff
        assert sck == ck
        assert scsn == start_scsn + 1
        assert message['type'] == 'server-auth'
        assert message['your_cookie'] == cck
        assert 'responders' not in message
        assert not message['initiator_connected']

        yield from client.close()

    @pytest.mark.asyncio
    def test_initiator_invalid_source_after_handshake(self, sleep, pack_nonce, client_factory):
        initiator, data = yield from client_factory(initiator_handshake=True)
        cck, ccsn = data['cck'], data['ccsn']

        # Set invalid source
        yield from initiator.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'whatever',
        })

        # Expect protocol error
        yield from sleep()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_responder_invalid_source_after_handshake(self, sleep, pack_nonce, client_factory):
        responder, data = yield from client_factory(responder_handshake=True)
        cck, ccsn = data['cck'], data['ccsn']

        # Set invalid source
        yield from responder.send(pack_nonce(cck, 0x01, 0x00, ccsn), {
            'type': 'whatever',
        })

        # Expect protocol error
        yield from sleep()
        assert not responder.ws_client.open
        assert responder.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_destination_after_handshake(self, sleep, pack_nonce, client_factory):
        responder, data = yield from client_factory(responder_handshake=True)
        id_, cck, ccsn = data['id'], data['cck'], data['ccsn']

        # Set invalid source
        yield from responder.send(pack_nonce(cck, id_, id_, ccsn), {
            'type': 'whatever',
        })

        # Expect protocol error
        yield from sleep()
        assert not responder.ws_client.open
        assert responder.ws_client.close_code == saltyrtc.CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_new_initiator(self, client_factory):
        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        # No initiator connected
        assert not r['initiator_connected']

        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        # Responder is connected
        assert i['responders'] == [r['id']]

        # new-initiator
        message, _, sck, s, d, scsn = yield from responder.recv()
        assert s == 0x00
        assert d == r['id']
        assert r['sck'] == sck
        assert scsn == r['start_scsn'] + 2
        assert message['type'] == 'new-initiator'

        # Bye
        yield from initiator.close()
        yield from responder.close()

    @pytest.mark.asyncio
    def test_new_responder(self, client_factory):
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        # No responder connected
        assert len(i['responders']) == 0

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        # Initiator connected
        assert r['initiator_connected']

        # new-responder
        message, _, sck, s, d, scsn = yield from initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == i['start_scsn'] + 2
        assert message['type'] == 'new-responder'
        assert message['id'] == r['id']

        # Bye
        yield from initiator.close()
        yield from responder.close()

    @pytest.mark.asyncio
    def test_multiple_initiators(self, sleep, client_factory):
        # First initiator handshake
        first_initiator, i = yield from client_factory(initiator_handshake=True)
        # No responder connected
        assert len(i['responders']) == 0

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        # Initiator connected
        assert r['initiator_connected']

        # new-responder
        yield from first_initiator.recv()

        # Second initiator handshake
        second_initiator, i = yield from client_factory(initiator_handshake=True)
        # Responder is connected
        assert i['responders'] == [r['id']]

        # First initiator: Expect drop by initiator
        yield from sleep()
        assert not first_initiator.ws_client.open
        assert responder.ws_client.close_code == saltyrtc.CloseCode.drop_by_initiator

        # new-initiator
        message, _, sck, s, d, scsn = yield from responder.recv()
        assert s == 0x00
        assert d == r['id']
        assert r['sck'] == sck
        assert scsn == r['start_scsn'] + 2
        assert message['type'] == 'new-initiator'

        # Bye
        yield from first_initiator.close()
        yield from responder.close()

    @pytest.mark.asyncio
    def test_multiple_responders(self, client_factory):
        pass
