"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import asyncio

import libnacl.public
import pytest
import websockets

from saltyrtc.server.common import (
    SIGNED_KEYS_CIPHERTEXT_LENGTH,
    CloseCode,
)


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
        assert client.close_code == CloseCode.subprotocol_error

    @pytest.mark.asyncio
    def test_invalid_subprotocols(self, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = yield from ws_client_factory(subprotocols=['kittie-protocol-3000'])
        yield from sleep()
        assert not client.open
        assert client.close_code == CloseCode.subprotocol_error

    @pytest.mark.asyncio
    def test_invalid_path_length(self, url, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = yield from ws_client_factory(path='{}/{}'.format(url, 'rawr!!!'))
        yield from sleep()
        assert not client.open
        assert client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_path_symbols(self, url, sleep, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = yield from ws_client_factory(path='{}/{}'.format(url, 'äöüä' * 16))
        yield from sleep()
        assert not client.open
        assert client.close_code == CloseCode.protocol_error

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
    def test_invalid_message_type(
            self, sleep, cookie_factory, pack_nonce, client_factory
    ):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'meow-hello'
        })
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_field_missing(self, sleep, cookie_factory, pack_nonce, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello'
        })
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_field(self, sleep, cookie_factory, pack_nonce, client_factory):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = yield from client_factory()
        yield from client.recv()
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello',
            'key': b'meow?'
        })
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

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
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_repeated_cookie(
            self, sleep, cookie_factory, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when a client
        sends an invalid cookie in 'client-auth'.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, scsn = yield from client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccsn = cookie_factory(), 2**32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': b'\x11' * 16,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_initiator_invalid_source(
            self, sleep, cookie_factory, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by an initiator.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()

        # client-hello
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x01, 0x00, ccsn), {
            'type': 'client-hello',
            'key': initiator_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_responder_invalid_source(
            self, sleep, cookie_factory, responder_key, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by a responder.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()

        # client-hello
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0xff, 0x00, ccsn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_invalid_destination(
            self, sleep, cookie_factory, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid destination address is being used by a client.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()

        # client-hello
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0xff, ccsn), {
            'type': 'client-hello',
            'key': initiator_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_subprotocol_downgrade_1(
            self, sleep, cookie_factory, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that the server drops the client in case it doesn't find
        a common subprotocol.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': ['v1.meow.lolcats.org', 'v2.meow'],
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.saltyrtc.have_internal
    @pytest.mark.asyncio
    def test_subprotocol_downgrade_2(
            self, monkeypatch,
            sleep, server, cookie_factory, initiator_key, pack_nonce, client_factory
    ):
        """
        Check that the server drops the client in case it detects a
        subprotocol downgrade.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # Patch server's list of subprotocols
        subprotocols = ['v1.meow.lolcats.org'] + pytest.saltyrtc.subprotocols
        monkeypatch.setattr(server, 'subprotocols', subprotocols)

        # client-auth
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': ['v1.meow.lolcats.org'] + pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_initiator_handshake(
            self, cookie_factory, initiator_key, pack_nonce, client_factory,
            server_permanent_key
    ):
        """
        Check that we can do a complete handshake for an initiator.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()
        ssk = message['key']
        client.box = libnacl.public.Box(sk=initiator_key, pk=ssk)

        # client-auth
        cck, ccsn = cookie_factory(), 2**32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # server-auth
        client.sign_box = libnacl.public.Box(
            sk=initiator_key, pk=server_permanent_key.pk)
        message, nonce, ck, s, d, scsn = yield from client.recv()
        assert s == 0x00
        assert d == 0x01
        assert sck == ck
        assert scsn == start_scsn + 1
        assert message['type'] == 'server-auth'
        assert message['your_cookie'] == cck
        assert len(message['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
        keys = client.sign_box.decrypt(message['signed_keys'], nonce=nonce)
        assert keys == ssk + initiator_key.pk
        assert 'initiator_connected' not in message
        assert len(message['responders']) == 0

        yield from client.close()

    @pytest.mark.asyncio
    def test_responder_handshake(
            self, cookie_factory, responder_key, pack_nonce, client_factory,
            server_permanent_key
    ):
        """
        Check that we can do a complete handshake for a responder.
        """
        client = yield from client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = yield from client.recv()
        ssk = message['key']

        # client-hello
        cck, ccsn = cookie_factory(), 2**32 - 1
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        ccsn += 1

        # client-auth
        client.box = libnacl.public.Box(sk=responder_key, pk=ssk)
        yield from client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # server-auth
        client.sign_box = libnacl.public.Box(
            sk=responder_key, pk=server_permanent_key.pk)
        message, nonce, ck, s, d, scsn = yield from client.recv()
        assert s == 0x00
        assert 0x01 < d <= 0xff
        assert sck == ck
        assert scsn == start_scsn + 1
        assert message['type'] == 'server-auth'
        assert message['your_cookie'] == cck
        assert len(message['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
        signed_keys = client.sign_box.decrypt(message['signed_keys'], nonce=nonce)
        assert signed_keys == ssk + responder_key.pk
        assert 'responders' not in message
        assert not message['initiator_connected']

        yield from client.close()

    @pytest.mark.asyncio
    def test_client_factory_handshake(
            self, client_factory, initiator_key, responder_key
    ):
        """
        Check that we can do a complete handshake using the client factory.
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        assert len(i['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
        signed_keys = initiator.sign_box.decrypt(
            i['signed_keys'], nonce=i['nonces']['server-auth'])
        assert signed_keys == i['ssk'] + initiator_key.pk
        yield from initiator.close()

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        assert len(r['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
        signed_keys = responder.sign_box.decrypt(
            r['signed_keys'], nonce=r['nonces']['server-auth'])
        assert signed_keys == r['ssk'] + responder_key.pk
        yield from responder.close()

    @pytest.saltyrtc.have_internal
    @pytest.mark.asyncio
    def test_keep_alive_pings_initiator(self, server, client_factory):
        """
        Check that the server sends ping messages in the requested
        interval.
        """
        if pytest.saltyrtc.external_server:
            return  # TODO: Remove after merge with update-cli

        # Initiator handshake
        initiator, i = yield from client_factory(
            ping_interval=1,
            initiator_handshake=True
        )

        # Wait for two pings (including pongs)
        yield from asyncio.sleep(2.1)

        # Check ping counter
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        assert protocol.client.keep_alive_pings == 2

        # Bye
        yield from initiator.close()

    @pytest.mark.asyncio
    def test_keep_alive_pings_responder(self, server, client_factory):
        """
        Check that the server sends ping messages in the requested
        interval.
        """
        if pytest.saltyrtc.external_server:
            return  # TODO: Remove after merge with update-cli

        # Responder handshake
        responder, r = yield from client_factory(
            ping_interval=1,
            responder_handshake=True
        )

        # Wait for two pings (including pongs)
        yield from asyncio.sleep(1.1)

        # Check ping counter
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        assert protocol.client.keep_alive_pings == 1

        # Bye
        yield from responder.close()

    @pytest.mark.asyncio
    def test_keep_alive_timeout(
            self, sleep, server, ws_client_factory, client_factory
    ):
        """
        Monkey-patch the the server's keep alive interval and timeout
        and check that the server sends us a ping and waits for a
        pong.
        """
        # Create client and patch it to not answer pings
        ws_client = yield from ws_client_factory()
        ws_client.pong = asyncio.coroutine(lambda *args, **kwargs: None)

        # Patch server's keep alive interval and timeout
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client.keep_alive_interval = 0
        protocol.client.keep_alive_timeout = 0.001

        # Initiator handshake
        client, i = yield from client_factory(
            ws_client=ws_client, initiator_handshake=True)

        # Expect protocol error
        yield from sleep()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

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
        assert initiator.ws_client.close_code == CloseCode.protocol_error

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
        assert responder.ws_client.close_code == CloseCode.protocol_error

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
        assert responder.ws_client.close_code == CloseCode.protocol_error

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
        assert actual_close_code == CloseCode.drop_by_initiator

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
        assert actual_close_code == CloseCode.drop_by_initiator

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
        assert actual_close_code == CloseCode.drop_by_initiator

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
    def test_drop_responder_with_reason(self, sleep, pack_nonce, client_factory):
        """
        Check that a responder can be dropped with a custom reason.
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        assert len(i['responders']) == 0

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        assert r['initiator_connected']

        # Drop responder with a different reason
        yield from initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r['id'],
            'reason': CloseCode.no_shared_tasks.value,
        })

        # Responder: Expect reason 'handover'
        yield from sleep()
        assert not responder.ws_client.open
        actual_close_code = responder.ws_client.close_code
        assert actual_close_code == CloseCode.no_shared_tasks

        # Bye
        yield from initiator.close()

    @pytest.mark.asyncio
    def test_drop_responder_invalid_reason(self, sleep, pack_nonce, client_factory):
        """
        Check that the server drops an initiator that uses a close code
        that is not accepted as drop reason.
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        assert len(i['responders']) == 0

        # Drop responder with a different reason
        yield from initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0xff,
            'reason': CloseCode.path_full_error.value,
        })

        # Expect protocol error
        yield from sleep()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

    @pytest.saltyrtc.have_internal
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
        assert initiator.ws_client.close_code == CloseCode.protocol_error

        # Bye
        yield from first_responder.close()
        yield from second_responder.close()

    @pytest.mark.asyncio
    def test_relay_errors(
            self, sleep, pack_nonce, cookie_factory, client_factory
    ):
        """
        Try sending relay messages to:
        1. An unregistered but valid destination
        2. An invalid destination
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 65424
        i['rcck'] = cookie_factory()

        # Send relay message to an unregistered destination
        nonce = pack_nonce(i['rcck'], i['id'], 0x02, i['rccsn'])
        data = yield from initiator.send(nonce, {
            'type': 'meow?',
        }, box=None)

        # Receive send-error message: initiator <-- initiator
        message, _, sck, s, d, scsn = yield from initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert sck == i['sck']
        assert scsn == i['start_scsn'] + 2
        assert message['type'] == 'send-error'
        assert message['id'] == data[16:]

        # Send relay message to an invalid destination
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], 0x01, i['rccsn']), {
            'type': 'h3h3-pwnz',
        }, box=None)

        # Expect protocol error
        yield from sleep()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    def test_relay_unencrypted(self, pack_nonce, cookie_factory, client_factory):
        """
        Check that the initiator and responder can communicate raw
        messages with each other (not encrypted).
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 98798984
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 24
        r['icck'] = cookie_factory()

        # new-responder
        yield from initiator.recv()

        # Send relay message: initiator --> responder
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'meow',
            'rawr': True,
        }, box=None)
        i['rccsn'] += 1

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = yield from responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn'] - 1
        assert message['type'] == 'meow'
        assert message['rawr']

        # Send relay message: initiator <-- responder
        yield from responder.send(pack_nonce(r['icck'], r['id'], i['id'], r['iccsn']), {
            'type': 'meow',
            'rawr': False,
        }, box=None)
        r['iccsn'] += 1

        # Receive relay message: initiator <-- responder
        message, _, ck, s, d, csn = yield from initiator.recv(box=None)
        assert ck == r['icck']
        assert s == r['id']
        assert d == i['id']
        assert csn == r['iccsn'] - 1
        assert message['type'] == 'meow'
        assert not message['rawr']

        # Bye
        yield from initiator.close()
        yield from responder.close()

    @pytest.mark.asyncio
    def test_relay_encrypted(
            self, initiator_key, responder_key, pack_nonce, cookie_factory, client_factory
    ):
        """
        Check that the initiator and responder can communicate raw
        messages with each other (encrypted).
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 456987
        i['rcck'] = cookie_factory()
        i['rbox'] = libnacl.public.Box(sk=initiator_key, pk=responder_key.pk)

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 24
        r['icck'] = cookie_factory()
        r['ibox'] = libnacl.public.Box(sk=responder_key, pk=initiator_key.pk)

        # new-responder
        yield from initiator.recv()

        # Send relay message: initiator --> responder
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'meow',
            'rawr': True,
        }, box=i['rbox'])
        i['rccsn'] += 1

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = yield from responder.recv(box=r['ibox'])
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn'] - 1
        assert message['type'] == 'meow'
        assert message['rawr']

        # Send relay message: initiator <-- responder
        yield from responder.send(pack_nonce(r['icck'], r['id'], i['id'], r['iccsn']), {
            'type': 'meow',
            'rawr': False,
        }, box=r['ibox'])
        r['iccsn'] += 1

        # Receive relay message: initiator <-- responder
        message, _, ck, s, d, csn = yield from initiator.recv(box=i['rbox'])
        assert ck == r['icck']
        assert s == r['id']
        assert d == i['id']
        assert csn == r['iccsn'] - 1
        assert message['type'] == 'meow'
        assert not message['rawr']

        # Bye
        yield from initiator.close()
        yield from responder.close()

    @pytest.mark.asyncio
    def test_relay_receiver_offline(
            self, pack_nonce, cookie_factory, client_factory
    ):
        """
        Check that the server responds with a `send-error` message in
        case the recipient is not available.
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 5846
        i['rcck'] = cookie_factory()

        # Send relay message: initiator --> responder (offline)
        nonce = pack_nonce(i['rcck'], i['id'], 0x02, i['rccsn'])
        data = yield from initiator.send(nonce, {
            'type': 'meow',
            'rawr': True,
        }, box=None)
        i['rccsn'] += 1

        # Receive send-error message: initiator <-- initiator
        message, _, sck, s, d, scsn = yield from initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert sck == i['sck']
        assert scsn == i['start_scsn'] + 2
        assert message['type'] == 'send-error'
        assert message['id'] == data[16:]

        # Bye
        yield from initiator.close()

    @pytest.saltyrtc.have_internal
    @pytest.mark.asyncio
    def test_peer_csn_in_overflow(
            self, sleep, pack_nonce, cookie_factory, client_factory, server
    ):
        """
        Check that the server does not validate the CSN for relay
        messages. It MUST ignore:
        1. Going back in time (a decreased peer CSN)
        2. A CSN that would create an overflow
        3. A repeated CSN
        """
        # Initiator handshake
        initiator, i = yield from client_factory(csn=0, initiator_handshake=True)
        i['rccsn'] = 2578  # Start peer CSN
        i['rcck'] = cookie_factory()

        # Patch server's combined sequence number of the initiator instance
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client.combined_sequence_number_in = 2 ** 48 - 1
        assert isinstance(protocol.client.combined_sequence_number_in, int)
        protocol.client.combined_sequence_number_in += 1
        assert not isinstance(protocol.client.combined_sequence_number_in, int)
        i['ccsn'] = 0  # Invalid!

        # Responder handshake
        responder, r = yield from client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 24
        r['icck'] = cookie_factory()

        # new-responder
        yield from initiator.recv()

        # Send relay message: initiator --> responder
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'meow',
        }, box=None)
        i['rccsn'] += 1

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = yield from responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn'] - 1
        assert message['type'] == 'meow'

        # Send relay message: initiator --> responder
        i['rccsn'] = 0  # Going back in time
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'rawr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = yield from responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn']
        assert message['type'] == 'rawr'

        # Send relay message: initiator --> responder
        i['rccsn'] = 2 ** 48 - 1  # This would create an overflow sentinel
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'rawr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = yield from responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn']
        assert message['type'] == 'rawr'

        # Send relay message: initiator --> responder
        i['rccsn'] = 2 ** 48 - 1  # This would create an overflow sentinel, also repeated
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'arrrrrrrr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = yield from responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn']
        assert message['type'] == 'arrrrrrrr'

        # Increase CSN (Overflow sentinel is set, client should be dropped)
        yield from initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0x02,
        })

        # Expect protocol error
        yield from sleep()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

        # Bye
        yield from responder.close()

    @pytest.saltyrtc.have_internal
    @pytest.mark.asyncio
    def test_peer_csn_out_overflow(
            self, sleep, pack_nonce, server, client_factory, cookie_factory
    ):
        """
        Check that the server does not take its own CSN for outgoing
        messages into account when relaying a message.
        """
        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 50217
        i['rcck'] = cookie_factory()

        # Patch server's combined sequence number of the initiator instance
        assert len(server.protocols) == 1
        i_protocol = next(iter(server.protocols))
        i_protocol.client.combined_sequence_number_out = 2 ** 48 - 1

        # Connect a new responder
        first_responder, r1 = yield from client_factory(responder_handshake=True)
        r1['iccsn'] = 2 ** 24
        r1['icck'] = cookie_factory()

        # Patch server's combined sequence number of the responder instance
        assert len(server.protocols) == 2
        r1_protocol = None
        for protocol in server.protocols:
            if protocol != i_protocol:
                r1_protocol = protocol
                break
        r1_protocol.client.combined_sequence_number_out = 2 ** 48 - 1
        assert isinstance(r1_protocol.client.combined_sequence_number_out, int)
        r1_protocol.client.combined_sequence_number_out += 1
        assert not isinstance(r1_protocol.client.combined_sequence_number_out, int)

        # new-responder
        message, _, sck, s, d, scsn = yield from initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == 2 ** 48 - 1
        assert message['id'] == r1['id']

        # Send relay message: initiator --> responder
        yield from initiator.send(pack_nonce(i['rcck'], i['id'], r1['id'], i['rccsn']), {
            'type': 'rawr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = yield from first_responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r1['id']
        assert csn == i['rccsn']
        assert message['type'] == 'rawr'

        # Connect a new responder
        second_responder, r = yield from client_factory(responder_handshake=True)

        # Expect protocol error
        yield from sleep()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

        # Bye
        yield from first_responder.close()
        yield from second_responder.close()

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
        assert exc_info.value.code == CloseCode.path_full_error

        # Close all clients
        tasks = [client.close() for client, _ in clients]
        yield from asyncio.wait(tasks, loop=event_loop)
