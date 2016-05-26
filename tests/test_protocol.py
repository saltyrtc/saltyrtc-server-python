"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import asyncio

import pytest
import libnacl.public
import websockets

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
        """
        Check that the server closes with Protocol Error when a client
        uses the same cookie as the server does.
        """
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
    def test_initiator_invalid_source(
            self, sleep, cookie, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by an initiator.
        """
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
    def test_responder_invalid_source(
            self, sleep, cookie, responder_key, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by a responder.
        """
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
    def test_invalid_destination(
            self, sleep, cookie, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid destination address is being used by a client.
        """
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
    def test_initiator_handshake(
            self, cookie, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that we can do a complete handshake for an initiator.
        """
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
    def test_responder_handshake(
            self, cookie, responder_key, pack_nonce, client_factory
    ):
        """
        Check that we can do a complete handshake for a responder.
        """
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
    def test_initiator_invalid_source_after_handshake(
            self, sleep, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by an initiator.
        """
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
    def test_responder_invalid_source_after_handshake(
            self, sleep, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by a responder.
        """
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
    def test_invalid_destination_after_handshake(
            self, sleep, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid destination address is being used by a client.
        """
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
        """
        Check that the 'new-initiator' message is sent to an already
        connected responder as soon as the initiator connects.
        """
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
        """
        Check that the 'new-responder' message is sent to an already
        connected initiator as soon as the responder connects.
        """
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
        """
        Ensure that the first initiator is being dropped properly
        when another initiator connects. Also check that the responder
        receives the 'new-initiator' message at the correct point in
        time.
        """
        # First initiator handshake
        first_initiator, i = yield from client_factory(initiator_handshake=True)
        # No responder connected
        assert len(i['responders']) == 0

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        # Initiator connected
        assert r['initiator_connected']

        # Second initiator handshake
        second_initiator, i = yield from client_factory(initiator_handshake=True)
        # Responder is connected
        assert i['responders'] == [r['id']]

        # First initiator: Expect drop by initiator
        yield from sleep()
        assert not first_initiator.ws_client.open
        actual_close_code = first_initiator.ws_client.close_code
        assert actual_close_code == saltyrtc.CloseCode.drop_by_initiator

        # new-initiator
        message, _, sck, s, d, scsn = yield from responder.recv()
        assert s == 0x00
        assert d == r['id']
        assert r['sck'] == sck
        assert scsn == r['start_scsn'] + 2
        assert message['type'] == 'new-initiator'

        # Bye
        yield from second_initiator.close()
        yield from responder.close()

    @pytest.mark.asyncio
    def test_drop_responder(self, sleep, pack_nonce, client_factory):
        """
        Check that dropping responders works on multiple responders.
        """
        # First responder handshake
        first_responder, r1 = yield from client_factory(responder_handshake=True)
        assert not r1['initiator_connected']

        # Second responder (the only one that will not be dropped) handshake
        second_responder, r2 = yield from client_factory(responder_handshake=True)
        assert not r2['initiator_connected']

        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        assert set(i['responders']) == {r1['id'], r2['id']}

        # Third responder handshake
        third_responder, r3 = yield from client_factory(responder_handshake=True)
        assert r3['initiator_connected']

        # new-responder
        message, _, sck, s, d, scsn = yield from initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == i['start_scsn'] + 2
        assert message['id'] == r3['id']

        # Drop first responder
        yield from initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r1['id'],
        })
        i['ccsn'] += 1

        # First responder: Expect drop by initiator
        yield from sleep()
        assert not first_responder.ws_client.open
        actual_close_code = first_responder.ws_client.close_code
        assert actual_close_code == saltyrtc.CloseCode.drop_by_initiator

        # Drop third responder
        yield from initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r3['id'],
        })
        i['ccsn'] += 1

        # Third responder: Expect drop by initiator
        yield from sleep()
        assert not third_responder.ws_client.open
        actual_close_code = third_responder.ws_client.close_code
        assert actual_close_code == saltyrtc.CloseCode.drop_by_initiator

        # Second responder: Still open
        assert second_responder.ws_client.open

        # Bye
        yield from second_responder.close()
        yield from initiator.close()

    @pytest.mark.asyncio
    def test_drop_invalid_responder(self, pack_nonce, client_factory):
        """
        Check that dropping a non-existing responder does not raise
        any errors.
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        # No responder connected
        assert len(i['responders']) == 0

        # Drop some responder
        yield from initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0xff,
        })
        i['ccsn'] += 1

        # Bye
        yield from initiator.close()

    @pytest.mark.asyncio
    def test_path_full(self, event_loop, client_factory):
        """
        Add 253 responder to a path. Then, add a 254th responder and
        check that the correct error code (Path Full) is being
        returned.

        Note: This test takes a few seconds.
        """
        tasks = [client_factory(responder_handshake=True, timeout=20.0)
                 for _ in range(0x02, 0x100)]
        clients = yield from asyncio.gather(*tasks, loop=event_loop)

        # All clients must be open
        assert all((client.ws_client.open for client, _ in clients))

        # Now the path is full
        with pytest.raises(websockets.ConnectionClosed) as exc_info:
            yield from client_factory(responder_handshake=True)
        assert exc_info.value.code == saltyrtc.CloseCode.path_full_error

        # Close all clients
        tasks = [client.close() for client, _ in clients]
        yield from asyncio.wait(tasks, loop=event_loop)

    @pytest.mark.asyncio
    def test_combined_sequence_number_overflow(
            self, sleep, server, client_factory
    ):
        """
        Monkey-patch the combined sequence number of the server and
        check that an overflow of the number is handled correctly.
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)

        # Patch server's combined sequence number of the initiator instance
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client.combined_sequence_number_out = 2 ** 48 - 1

        # Connect a new responder
        first_responder, r = yield from client_factory(responder_handshake=True)

        # new-responder
        message, _, sck, s, d, scsn = yield from initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == 2 ** 48 - 1
        assert message['id'] == r['id']

        # Connect a new responder
        second_responder, r = yield from client_factory(responder_handshake=True)

        # Expect protocol error
        yield from sleep()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == saltyrtc.CloseCode.protocol_error

        # Bye
        yield from first_responder.close()
        yield from second_responder.close()
