"""
The tests provided in this module make sure that the server is
compliant to the SaltyRTC protocol.
"""
import asyncio

import libnacl.public
import pytest
import websockets

from saltyrtc.server import ServerProtocol
from saltyrtc.server.common import (
    SIGNED_KEYS_CIPHERTEXT_LENGTH,
    ClientState,
    CloseCode,
)


class _FakePathClient:
    def __init__(self) -> None:
        self.connection_closed_future = asyncio.Future()
        self.connection_closed_future.set_result(None)
        self.state = ClientState.restricted
        self.id = None

    def update_log_name(self, id_):
        pass

    def authenticate(self, id_):
        self.id = id_
        self.state = ClientState.authenticated


@pytest.mark.usefixtures('evaluate_log')
class TestProtocol:
    @pytest.mark.asyncio
    async def test_no_subprotocols(self, server, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = await ws_client_factory(subprotocols=None)
        await server.wait_most_recent_connection_closed()
        assert not client.open
        assert client.close_code == CloseCode.subprotocol_error
        assert len(server.protocols) == 0

    @pytest.mark.asyncio
    async def test_invalid_subprotocols(self, server, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *1002*.
        """
        client = await ws_client_factory(subprotocols=['kittie-protocol-3000'])
        await server.wait_most_recent_connection_closed()
        assert not client.open
        assert client.close_code == CloseCode.subprotocol_error
        assert len(server.protocols) == 0

    @pytest.mark.asyncio
    async def test_invalid_path_length(self, url_factory, server, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = await ws_client_factory(path='{}/{}'.format(
            url_factory(), 'rawr!!!'))
        await server.wait_most_recent_connection_closed()
        assert not client.open
        assert client.close_code == CloseCode.protocol_error
        assert len(server.protocols) == 0

    @pytest.mark.asyncio
    async def test_invalid_path_symbols(self, url_factory, server, ws_client_factory):
        """
        The server must drop the client after the connection has been
        established with a close code of *3001*.
        """
        client = await ws_client_factory(path='{}/{}'.format(
            url_factory(), 'äöüä' * 16))
        await server.wait_most_recent_connection_closed()
        assert not client.open
        assert client.close_code == CloseCode.protocol_error
        assert len(server.protocols) == 0

    @pytest.mark.asyncio
    async def test_invalid_message_str(self, server, ws_client_factory):
        """
        The server must discard string messages.
        """
        client = await ws_client_factory()
        await client.send('m30w' * 10)
        await server.wait_connections_closed()
        assert not client.open
        assert client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_server_hello(self, server, client_factory):
        """
        The server must send a valid `server-hello` on connection.
        """
        client = await client_factory()
        message, _, sck, s, d, scsn = await client.recv()
        assert s == d == 0x00
        assert scsn & 0xffff00000000 == 0
        assert message['type'] == 'server-hello'
        assert len(message['key']) == 32
        await client.ws_client.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_invalid_message_type(
            self, cookie_factory, pack_nonce, server, client_factory
    ):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = await client_factory()
        await client.recv()
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'meow-hello'
        })
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_field_missing(
            self, cookie_factory, pack_nonce, server, client_factory
    ):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = await client_factory()
        await client.recv()
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello'
        })
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_invalid_field(
            self, cookie_factory, pack_nonce, server, client_factory
    ):
        """
        The server must close the connection when an invalid packet has
        been sent during the handshake with a close code of *3001*.
        """
        client = await client_factory()
        await client.recv()
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello',
            'key': b'meow?'
        })
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_invalid_message_length(
            self, cookie_factory, pack_nonce, server, client_factory
    ):
        """
        The server must close the connection when a packet containing
        less than 25 bytes has been received.
        """
        client = await client_factory()
        await client.recv()
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), b'', pack=False)
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_duplicated_cookie(
            self, initiator_key, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when a client
        uses the same cookie as the server does.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, scsn = await client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccsn = sck, 2**32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_invalid_repeated_cookie(
            self, cookie_factory, initiator_key, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when a client
        sends an invalid cookie in 'client-auth'.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, scsn = await client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccsn = cookie_factory(), 2**32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': b'\x11' * 16,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_initiator_invalid_source(
            self, cookie_factory, initiator_key, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by an initiator.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()

        # client-hello
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x01, 0x00, ccsn), {
            'type': 'client-hello',
            'key': initiator_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_responder_invalid_source(
            self, cookie_factory, responder_key, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by a responder.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()

        # client-hello
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0xff, 0x00, ccsn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_invalid_destination(
            self, cookie_factory, initiator_key, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid destination address is being used by a client.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()

        # client-hello
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x00, 0xff, ccsn), {
            'type': 'client-hello',
            'key': initiator_key.pk,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_subprotocol_downgrade_1(
            self, cookie_factory, initiator_key, pack_nonce, server, client_factory
    ):
        """
        Check that the server drops the client in case it doesn't find
        a common subprotocol.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # client-auth
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': ['v1.meow.lolcats.org', 'v2.meow'],
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_subprotocol_downgrade_2(
            self, monkeypatch, cookie_factory, initiator_key, pack_nonce, server,
            client_factory
    ):
        """
        Check that the server drops the client in case it detects a
        subprotocol downgrade.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()
        client.box = libnacl.public.Box(sk=initiator_key, pk=message['key'])

        # Patch server's list of subprotocols
        subprotocols = ['v1.meow.lolcats.org'] + pytest.saltyrtc.subprotocols
        monkeypatch.setattr(server, 'subprotocols', subprotocols)

        # client-auth
        cck, ccsn = cookie_factory(), 2 ** 32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': ['v1.meow.lolcats.org'] + pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_initiator_handshake_unencrypted(
            self, cookie_factory, pack_nonce, server, client_factory
    ):
        """
        Check that we cannot do a complete handshake for an initiator
        when 'client-auth' is not encrypted.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()

        # client-auth
        cck, ccsn = cookie_factory(), 2**32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_initiator_handshake(
            self, cookie_factory, initiator_key, pack_nonce, server, client_factory,
            server_permanent_keys
    ):
        """
        Check that we can do a complete handshake for an initiator.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()
        ssk = message['key']
        client.box = libnacl.public.Box(sk=initiator_key, pk=ssk)

        # client-auth
        cck, ccsn = cookie_factory(), 2**32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # server-auth
        client.sign_box = libnacl.public.Box(
            sk=initiator_key, pk=server_permanent_keys[0].pk)
        message, nonce, ck, s, d, scsn = await client.recv()
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

        await client.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_responder_handshake(
            self, cookie_factory, responder_key, pack_nonce, client_factory, server,
            server_permanent_keys
    ):
        """
        Check that we can do a complete handshake for a responder.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()
        ssk = message['key']

        # client-hello
        cck, ccsn = cookie_factory(), 2**32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        ccsn += 1

        # client-auth
        client.box = libnacl.public.Box(sk=responder_key, pk=ssk)
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # server-auth
        client.sign_box = libnacl.public.Box(
            sk=responder_key, pk=server_permanent_keys[0].pk)
        message, nonce, ck, s, d, scsn = await client.recv()
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

        await client.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_responder_handshake_unencrypted(
            self, cookie_factory, responder_key, pack_nonce, client_factory, server
    ):
        """
        Check that we can do a complete handshake for a responder.
        """
        client = await client_factory()

        # server-hello, already checked in another test
        message, _, sck, s, d, start_scsn = await client.recv()

        # client-hello
        cck, ccsn = cookie_factory(), 2**32 - 1
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-hello',
            'key': responder_key.pk,
        })
        ccsn += 1

        # client-auth
        await client.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'client-auth',
            'your_cookie': sck,
            'subprotocols': pytest.saltyrtc.subprotocols,
        })
        ccsn += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not client.ws_client.open
        assert client.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_client_factory_handshake(
            self, server, client_factory, initiator_key, responder_key
    ):
        """
        Check that we can do a complete handshake using the client factory.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        assert len(i['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
        signed_keys = initiator.sign_box.decrypt(
            i['signed_keys'], nonce=i['nonces']['server-auth'])
        assert signed_keys == i['ssk'] + initiator_key.pk
        await initiator.close()

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        assert len(r['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
        signed_keys = responder.sign_box.decrypt(
            r['signed_keys'], nonce=r['nonces']['server-auth'])
        assert signed_keys == r['ssk'] + responder_key.pk
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_keep_alive_pings_initiator(self, sleep, server, client_factory):
        """
        Check that the server sends ping messages in the requested
        interval.
        """
        # Initiator handshake
        initiator, i = await client_factory(
            ping_interval=1,
            initiator_handshake=True
        )

        # Wait for two pings (including pongs)
        await sleep(2.1)

        # Check ping counter
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        assert protocol.client.keep_alive_pings == 2

        # Bye
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_keep_alive_pings_responder(self, sleep, server, client_factory):
        """
        Check that the server sends ping messages in the requested
        interval.
        """
        # Responder handshake
        responder, r = await client_factory(
            ping_interval=1,
            responder_handshake=True
        )

        # Wait for two pings (including pongs)
        await sleep(1.1)

        # Check ping counter
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        assert protocol.client.keep_alive_pings == 1

        # Bye
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_keep_alive_ignore_invalid(self, sleep, server, client_factory):
        """
        Check that the server ignores invalid keep alive intervals.
        """
        # Initiator handshake
        initiator, i = await client_factory(
            ping_interval=0,
            initiator_handshake=True
        )

        # Wait for a second
        await sleep(1.1)

        # Check ping counter
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        assert protocol.client.keep_alive_pings == 0

        # Bye
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_keep_alive_timeout(
            self, ws_client_factory, server, client_factory
    ):
        """
        Monkey-patch the server's keep alive interval and timeout and
        check that the server sends a ping and waits for a pong.
        """
        # Create client and patch it to not answer pings
        ws_client = await ws_client_factory()
        ws_client.pong = asyncio.coroutine(lambda *args, **kwargs: None)

        # Patch server's keep alive interval and timeout
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client._keep_alive_interval = 0
        protocol.client.keep_alive_timeout = 0.001

        # Initiator handshake
        await client_factory(ws_client=ws_client, initiator_handshake=True)

        # Expect protocol error
        await server.wait_connections_closed()
        assert not ws_client.open
        assert ws_client.close_code == CloseCode.timeout

    @pytest.mark.asyncio
    async def test_initiator_invalid_source_after_handshake(
            self, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by an initiator.
        """
        initiator, data = await client_factory(initiator_handshake=True)
        cck, ccsn = data['cck'], data['ccsn']

        # Set invalid source
        await initiator.send(pack_nonce(cck, 0x00, 0x00, ccsn), {
            'type': 'whatever',
        })

        # Expect protocol error
        await server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_responder_invalid_source_after_handshake(
            self, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid source address is being used by a responder.
        """
        responder, data = await client_factory(responder_handshake=True)
        cck, ccsn = data['cck'], data['ccsn']

        # Set invalid source
        await responder.send(pack_nonce(cck, 0x01, 0x00, ccsn), {
            'type': 'whatever',
        })

        # Expect protocol error
        await server.wait_connections_closed()
        assert not responder.ws_client.open
        assert responder.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_invalid_destination_after_handshake(
            self, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        invalid destination address is being used by a client.
        """
        responder, data = await client_factory(responder_handshake=True)
        id_, cck, ccsn = data['id'], data['cck'], data['ccsn']

        # Set invalid source
        await responder.send(pack_nonce(cck, id_, id_, ccsn), {
            'type': 'whatever',
        })

        # Expect protocol error
        await server.wait_connections_closed()
        assert not responder.ws_client.open
        assert responder.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_unencrypted_packet_after_initiator_handshake(
            self, pack_nonce, server, client_factory
    ):
        """
        Check that the server closes with Protocol Error when an
        unencrypted packet is being sent by an initiator.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        assert len(i['responders']) == 0

        # Drop non-existing responder (encrypted)
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0x02,
        })
        i['ccsn'] += 1

        # Drop non-existing responder (unencrypted)
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0x02,
        }, box=None)
        i['ccsn'] += 1

        # Expect protocol error
        await server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_new_initiator(self, server, client_factory):
        """
        Check that the 'new-initiator' message is sent to an already
        connected responder as soon as the initiator connects.
        """
        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        # No initiator connected
        assert not r['initiator_connected']

        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        # Responder is connected
        assert i['responders'] == [r['id']]

        # new-initiator
        message, _, sck, s, d, scsn = await responder.recv()
        assert s == 0x00
        assert d == r['id']
        assert r['sck'] == sck
        assert scsn == r['start_scsn'] + 2
        assert message['type'] == 'new-initiator'

        # Bye
        await initiator.close()
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_new_responder(self, server, client_factory):
        """
        Check that the 'new-responder' message is sent to an already
        connected initiator as soon as the responder connects.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        # No responder connected
        assert len(i['responders']) == 0

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        # Initiator connected
        assert r['initiator_connected']

        # new-responder
        message, _, sck, s, d, scsn = await initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == i['start_scsn'] + 2
        assert message['type'] == 'new-responder'
        assert message['id'] == r['id']

        # Bye
        await initiator.close()
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_multiple_initiators(self, server, client_factory):
        """
        Ensure that the first initiator is being dropped properly
        when another initiator connects. Also check that the responder
        receives the 'new-initiator' message at the correct point in
        time.
        """
        # First initiator handshake
        first_initiator, i = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()
        # No responder connected
        assert len(i['responders']) == 0

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        # Initiator connected
        assert r['initiator_connected']

        # Second initiator handshake
        second_initiator, i = await client_factory(initiator_handshake=True)
        # Responder is connected
        assert i['responders'] == [r['id']]

        # First initiator: Expect drop by initiator
        await connection_closed_future()
        assert not first_initiator.ws_client.open
        assert first_initiator.ws_client.close_code == CloseCode.drop_by_initiator

        # new-initiator
        message, _, sck, s, d, scsn = await responder.recv()
        assert s == 0x00
        assert d == r['id']
        assert r['sck'] == sck
        assert scsn == r['start_scsn'] + 2
        assert message['type'] == 'new-initiator'

        # Bye
        await second_initiator.close()
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_drop_responder(self, pack_nonce, server, client_factory):
        """
        Check that dropping responders works on multiple responders.
        """
        # First responder handshake
        first_responder, r1 = await client_factory(responder_handshake=True)
        first_responder_closed_future = server.wait_connection_closed_marker()
        assert not r1['initiator_connected']

        # Second responder (the only one that will not be dropped) handshake
        second_responder, r2 = await client_factory(responder_handshake=True)
        assert not r2['initiator_connected']

        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        assert set(i['responders']) == {r1['id'], r2['id']}

        # Third responder handshake
        third_responder, r3 = await client_factory(responder_handshake=True)
        third_responder_closed_future = server.wait_connection_closed_marker()
        assert r3['initiator_connected']

        # new-responder
        message, _, sck, s, d, scsn = await initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == i['start_scsn'] + 2
        assert message['id'] == r3['id']

        # Drop first responder
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r1['id'],
        })
        i['ccsn'] += 1

        # First responder: Expect drop by initiator
        await first_responder_closed_future()
        assert not first_responder.ws_client.open
        assert first_responder.ws_client.close_code == CloseCode.drop_by_initiator

        # Drop third responder
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r3['id'],
        })
        i['ccsn'] += 1

        # Third responder: Expect drop by initiator
        await third_responder_closed_future()
        assert not third_responder.ws_client.open
        assert third_responder.ws_client.close_code == CloseCode.drop_by_initiator

        # Second responder: Still open
        assert second_responder.ws_client.open

        # Bye
        await second_responder.close()
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_drop_invalid_responder(self, pack_nonce, server, client_factory):
        """
        Check that dropping a non-existing responder does not raise
        any errors.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        # No responder connected
        assert len(i['responders']) == 0

        # Drop some responder
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0xff,
        })
        i['ccsn'] += 1

        # Bye
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_drop_responder_with_reason(
            self, pack_nonce, server, client_factory
    ):
        """
        Check that a responder can be dropped with a custom reason.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        assert len(i['responders']) == 0

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()
        assert r['initiator_connected']

        # Drop responder with a different reason
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r['id'],
            'reason': CloseCode.internal_error.value,
        })

        # Responder: Expect reason 'internal error'
        await connection_closed_future()
        assert not responder.ws_client.open
        assert responder.ws_client.close_code == CloseCode.internal_error

        # Bye
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_drop_responder_invalid_reason(
            self, pack_nonce, server, client_factory
    ):
        """
        Check that the server drops an initiator that uses a close code
        that is not accepted as drop reason.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()
        assert len(i['responders']) == 0

        # Drop responder with a different reason
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0xff,
            'reason': CloseCode.path_full_error.value,
        })

        # Expect protocol error
        await connection_closed_future()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_combined_sequence_number_overflow(
            self, server, client_factory
    ):
        """
        Monkey-patch the combined sequence number of the server and
        check that an overflow of the number is handled correctly.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Patch server's combined sequence number of the initiator instance
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client._csn_out = 2 ** 48 - 1

        # Connect a new responder
        first_responder, r = await client_factory(responder_handshake=True)

        # new-responder
        message, _, sck, s, d, scsn = await initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == 2 ** 48 - 1
        assert message['id'] == r['id']

        # Connect a new responder
        second_responder, r = await client_factory(responder_handshake=True)

        # Expect protocol error
        await connection_closed_future()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

        # Bye
        await first_responder.close()
        await second_responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_errors(
            self, pack_nonce, cookie_factory, server, client_factory
    ):
        """
        Try sending relay messages to:
        1. An unregistered but valid destination
        2. An invalid destination
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 65424
        i['rcck'] = cookie_factory()

        # Send relay message to an unregistered destination
        nonce = pack_nonce(i['rcck'], i['id'], 0x02, i['rccsn'])
        data = await initiator.send(nonce, {
            'type': 'meow?',
        }, box=None)

        # Receive send-error message: initiator <-- initiator
        message, _, sck, s, d, scsn = await initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert sck == i['sck']
        assert scsn == i['start_scsn'] + 2
        assert message['type'] == 'send-error'
        assert len(message['id']) == 8
        assert message['id'] == data[16:24]

        # Send relay message to an invalid destination
        await initiator.send(pack_nonce(i['rcck'], i['id'], 0x01, i['rccsn']), {
            'type': 'h3h3-pwnz',
        }, box=None)

        # Expect protocol error
        await server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

    @pytest.mark.asyncio
    async def test_relay_unencrypted(
            self, pack_nonce, cookie_factory, server, client_factory
    ):
        """
        Check that the initiator and responder can communicate raw
        messages with each other (not encrypted).
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 98798984
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 24
        r['icck'] = cookie_factory()

        # new-responder
        await initiator.recv()

        # Send relay message: initiator --> responder
        await initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'meow',
            'rawr': True,
        }, box=None)
        i['rccsn'] += 1

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = await responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn'] - 1
        assert message['type'] == 'meow'
        assert message['rawr']

        # Send relay message: initiator <-- responder
        await responder.send(pack_nonce(r['icck'], r['id'], i['id'], r['iccsn']), {
            'type': 'meow',
            'rawr': False,
        }, box=None)
        r['iccsn'] += 1

        # Receive relay message: initiator <-- responder
        message, _, ck, s, d, csn = await initiator.recv(box=None)
        assert ck == r['icck']
        assert s == r['id']
        assert d == i['id']
        assert csn == r['iccsn'] - 1
        assert message['type'] == 'meow'
        assert not message['rawr']

        # Bye
        await initiator.close()
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_encrypted(
            self, initiator_key, responder_key, pack_nonce, cookie_factory, server,
            client_factory
    ):
        """
        Check that the initiator and responder can communicate raw
        messages with each other (encrypted).
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 456987
        i['rcck'] = cookie_factory()
        i['rbox'] = libnacl.public.Box(sk=initiator_key, pk=responder_key.pk)

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 24
        r['icck'] = cookie_factory()
        r['ibox'] = libnacl.public.Box(sk=responder_key, pk=initiator_key.pk)

        # new-responder
        await initiator.recv()

        # Send relay message: initiator --> responder
        await initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'meow',
            'rawr': True,
        }, box=i['rbox'])
        i['rccsn'] += 1

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = await responder.recv(box=r['ibox'])
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn'] - 1
        assert message['type'] == 'meow'
        assert message['rawr']

        # Send relay message: initiator <-- responder
        await responder.send(pack_nonce(r['icck'], r['id'], i['id'], r['iccsn']), {
            'type': 'meow',
            'rawr': False,
        }, box=r['ibox'])
        r['iccsn'] += 1

        # Receive relay message: initiator <-- responder
        message, _, ck, s, d, csn = await initiator.recv(box=i['rbox'])
        assert ck == r['icck']
        assert s == r['id']
        assert d == i['id']
        assert csn == r['iccsn'] - 1
        assert message['type'] == 'meow'
        assert not message['rawr']

        # Bye
        await initiator.close()
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_receiver_offline(
            self, pack_nonce, cookie_factory, server, client_factory
    ):
        """
        Check that the server responds with a `send-error` message in
        case the recipient is not available.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 5846
        i['rcck'] = cookie_factory()

        # Send relay message: initiator --> responder (offline)
        nonce = pack_nonce(i['rcck'], i['id'], 0x02, i['rccsn'])
        data = await initiator.send(nonce, {
            'type': 'meow',
            'rawr': True,
        }, box=None)
        i['rccsn'] += 1

        # Receive send-error message: initiator <-- initiator
        message, _, sck, s, d, scsn = await initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert sck == i['sck']
        assert scsn == i['start_scsn'] + 2
        assert message['type'] == 'send-error'
        assert len(message['id']) == 8
        assert message['id'] == data[16:24]

        # Bye
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_send_and_close(
            self, pack_nonce, cookie_factory, server, client_factory
    ):
        """
        Ensure relay messages are being dispatched in case the client
        closes after having sent a couple of relay messages.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 98798981
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 23
        r['icck'] = cookie_factory()

        # new-responder
        await initiator.recv()

        # Send 3 relay messages: initiator --> responder
        expected_data = b'\xfe' * 2**16  # 64 KiB
        for _ in range(3):
            nonce = pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn'])
            await initiator.send(nonce, expected_data, box=None)
            i['rccsn'] += 1

        # Close initiator
        await initiator.close()

        # Receive 3 relay messages: initiator --> responder
        for _ in range(3):
            actual_data, *_ = await responder.recv(box=None)
            assert actual_data == expected_data

        # Bye
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_send_before_close_responder(
            self, pack_nonce, cookie_factory, server, client_factory
    ):
        """
        Ensure relay messages are being dispatched in case the receiver
        is being closed (drop responder) after the sender has sent the
        relay messages.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 98798981
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        responder_closed_future = server.wait_connection_closed_marker()
        r['iccsn'] = 2 ** 23
        r['icck'] = cookie_factory()

        # new-responder
        await initiator.recv()

        # Send 6 relay messages: initiator --> responder
        expected_data = b'\xfe' * 2**15  # 32 KiB
        for _ in range(6):
            nonce = pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn'])
            await initiator.send(nonce, expected_data, box=None)
            i['rccsn'] += 1

        # Drop responder
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r['id'],
        })
        i['ccsn'] += 1

        # Receive 6 relay messages: initiator --> responder
        for _ in range(6):
            actual_data, *_ = await responder.recv(box=None)
            assert actual_data == expected_data

        # Responder: Expect drop by initiator
        await responder_closed_future()
        assert not responder.ws_client.open
        assert responder.ws_client.close_code == CloseCode.drop_by_initiator

        # Bye
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_send_before_close_initiator(
            self, pack_nonce, cookie_factory, server, client_factory
    ):
        """
        Ensure relay messages are being dispatched in case the receiver
        is being closed (drop initiator) after the sender has sent the
        relay messages.
        """
        # Initiator handshake
        first_initiator, i = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()
        i['rccsn'] = 98798981
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 23
        r['icck'] = cookie_factory()

        # new-responder
        await first_initiator.recv()

        # Send 6 relay messages: initiator <-- responder
        expected_data = b'\xfe' * 2**15  # 32 KiB
        for _ in range(6):
            nonce = pack_nonce(r['icck'], r['id'], i['id'], r['iccsn'])
            await responder.send(nonce, expected_data, box=None)
            r['iccsn'] += 1

        # Second initiator handshake
        second_initiator, i = await client_factory(initiator_handshake=True)
        # Responder is connected
        assert i['responders'] == [r['id']]

        # new-initiator
        await responder.recv()

        # Receive 6 relay messages: initiator <-- responder
        for _ in range(6):
            actual_data, *_ = await first_initiator.recv(box=None)
            assert actual_data == expected_data

        # First initiator: Expect drop by initiator
        await connection_closed_future()
        assert not first_initiator.ws_client.open
        assert first_initiator.ws_client.close_code == CloseCode.drop_by_initiator

        # Bye
        await responder.close()
        await second_initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_send_after_close(
            self, mocker, event_loop, pack_nonce, cookie_factory, server, client_factory,
            initiator_key
    ):
        """
        When the responder is being dropped by the initiator, the
        responder's task loop may await a long-blocking task before it
        is being closed. Ensure that the initiator is not able to
        enqueue further messages to the responder at that point.
        """
        # Mock the protocol to release the 'done_future' once the closing procedure has
        # been initiated
        class _MockProtocol(ServerProtocol):
            def _drop_client(self, *args, **kwargs):
                super()._drop_client(*args, **kwargs)
                done_future.set_result(None)

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 98798981
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 23
        r['icck'] = cookie_factory()

        # new-responder
        await initiator.recv()

        # Get responder's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_responder(r['id'])
        done_future = asyncio.Future(loop=event_loop)

        # Create long-blocking task
        async def blocking_task():
            await done_future

        # Enqueue long-blocking task
        await path_client.jobs.enqueue(blocking_task())

        # Drop responder
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r['id'],
        })
        i['ccsn'] += 1

        # Send relay message: initiator --> responder
        nonce = pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn'])
        await initiator.send(nonce, b'\xfe' * 2**15, box=None)
        i['rccsn'] += 1

        # Responder: Expect drop by initiator
        with pytest.raises(websockets.ConnectionClosed):
            await responder.recv(box=None)
        assert responder.ws_client.close_code == CloseCode.drop_by_initiator

        # Bye
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_receiver_connection_lost(
            self, mocker, event_loop, ws_client_factory, initiator_key, pack_nonce,
            cookie_factory, server, client_factory
    ):
        """
        Check that the server responds with a `send-error` message in
        case the message could not be sent to the recipient due to a
        connection loss.
        """
        initiator_ws_client = await ws_client_factory()
        responder_ws_client = await ws_client_factory()

        # Patch server's keep alive interval and timeout
        assert len(server.protocols) == 2
        for protocol in server.protocols:
            protocol.client._keep_alive_interval = 1.0
            protocol.client.keep_alive_timeout = 1.0

        # Initiator handshake
        initiator, i = await client_factory(
            ws_client=initiator_ws_client, initiator_handshake=True)
        i['rccsn'] = 98798984
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = await client_factory(
            ws_client=responder_ws_client, responder_handshake=True)
        r['iccsn'] = 2 ** 24
        r['icck'] = cookie_factory()

        # new-responder
        await initiator.recv()

        # Get path instance of server and responder's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_responder(0x02)

        # Mock responder instance: Block sending and let the next ping time out
        async def _mock_send(*_):
            path_client.log.notice('... NOT')
            await asyncio.Future(loop=event_loop)

        async def _mock_ping(*_):
            path_client.log.notice('... NOT')
            return asyncio.Future(loop=event_loop)

        mocker.patch.object(path_client._connection, 'send', _mock_send)
        mocker.patch.object(path_client._connection, 'ping', _mock_ping)

        # Send relay message: initiator --> responder (mocked)
        nonce = pack_nonce(i['rcck'], i['id'], 0x02, i['rccsn'])
        data = await initiator.send(nonce, {
            'type': 'meow',
            'rawr': True,
        }, box=None)
        i['rccsn'] += 1

        # Receive send-error message: initiator <-- initiator (mocked)
        message, _, sck, s, d, scsn = await initiator.recv(timeout=10.0)
        assert s == 0x00
        assert d == i['id']
        assert sck == i['sck']
        assert scsn == i['start_scsn'] + 3
        assert message['type'] == 'send-error'
        assert len(message['id']) == 8
        assert message['id'] == data[16:24]

        # Receive 'disconnected' message
        message, *_ = await initiator.recv()
        assert message == {'type': 'disconnected', 'id': r['id']}

        # Bye
        await initiator.close()
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_timeout(
            self, mocker, sleep, initiator_key, pack_nonce,
            cookie_factory, server, client_factory
    ):
        """
        Ensure the server responds with a 'send-error' message when a
        relay times out.
        """
        # Mock the job queue join timeout
        mocker.patch('saltyrtc.server.server.RELAY_TIMEOUT', 0.1)

        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 98798981
        i['rcck'] = cookie_factory()

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 23
        r['icck'] = cookie_factory()

        # new-responder
        await initiator.recv()

        # Get responder's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_responder(r['id'])
        send = path_client._connection.send

        # Mock responder instance: Slow-motion sending
        async def _mock_send(*args, **kwargs):
            await sleep(0.2)
            return await send(*args, **kwargs)

        mocker.patch.object(path_client._connection, 'send', _mock_send)

        # Send relay message: initiator --> responder
        nonce = pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn'])
        await initiator.send(nonce, b'\xfe' * 2**15, box=None)
        i['rccsn'] += 1

        # Receive send-error message: initiator <-- initiator
        message, *_ = await initiator.recv()
        assert message['type'] == 'send-error'
        assert len(message['id']) == 8

        # Bye
        await initiator.close()
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_peer_csn_in_overflow(
            self, pack_nonce, cookie_factory, server, client_factory
    ):
        """
        Check that the server does not validate the CSN for relay
        messages. It MUST ignore:
        1. Going back in time (a decreased peer CSN)
        2. A CSN that would create an overflow
        3. A repeated CSN
        """
        # Initiator handshake
        initiator, i = await client_factory(csn=0, initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()
        i['rccsn'] = 2578  # Start peer CSN
        i['rcck'] = cookie_factory()

        # Patch server's combined sequence number of the initiator instance
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client._csn_in = 2 ** 48 - 1
        assert isinstance(protocol.client.csn_in, int)
        protocol.client.increment_csn_in()
        assert not isinstance(protocol.client.csn_in, int)
        i['ccsn'] = 0  # Invalid!

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 24
        r['icck'] = cookie_factory()

        # new-responder
        await initiator.recv()

        # Send relay message: initiator --> responder
        await initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'meow',
        }, box=None)
        i['rccsn'] += 1

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = await responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn'] - 1
        assert message['type'] == 'meow'

        # Send relay message: initiator --> responder
        i['rccsn'] = 0  # Going back in time
        await initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'rawr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = await responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn']
        assert message['type'] == 'rawr'

        # Send relay message: initiator --> responder
        i['rccsn'] = 2 ** 48 - 1  # This would create an overflow sentinel
        await initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'rawr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = await responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn']
        assert message['type'] == 'rawr'

        # Send relay message: initiator --> responder
        i['rccsn'] = 2 ** 48 - 1  # This would create an overflow sentinel, also repeated
        await initiator.send(pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn']), {
            'type': 'arrrrrrrr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = await responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r['id']
        assert csn == i['rccsn']
        assert message['type'] == 'arrrrrrrr'

        # Increase CSN (Overflow sentinel is set, client should be dropped)
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': 0x02,
        })

        # Expect protocol error
        await connection_closed_future()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

        # Bye
        await responder.close()

    @pytest.mark.asyncio
    async def test_peer_csn_out_overflow(
            self, pack_nonce, server, client_factory, cookie_factory
    ):
        """
        Check that the server does not take its own CSN for outgoing
        messages into account when relaying a message.
        """
        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()
        i['rccsn'] = 50217
        i['rcck'] = cookie_factory()

        # Patch server's combined sequence number of the initiator instance
        assert len(server.protocols) == 1
        i_protocol = next(iter(server.protocols))
        i_protocol.client._csn_out = 2 ** 48 - 1

        # Connect a new responder
        first_responder, r1 = await client_factory(responder_handshake=True)
        r1['iccsn'] = 2 ** 24
        r1['icck'] = cookie_factory()

        # Patch server's combined sequence number of the responder instance
        assert len(server.protocols) == 2
        r1_protocol = None
        for protocol in server.protocols:
            if protocol != i_protocol:
                r1_protocol = protocol
                break
        r1_protocol.client._csn_out = 2 ** 48 - 1
        assert isinstance(r1_protocol.client.csn_out, int)
        r1_protocol.client.increment_csn_out()
        assert not isinstance(r1_protocol.client.csn_out, int)

        # new-responder
        message, _, sck, s, d, scsn = await initiator.recv()
        assert s == 0x00
        assert d == i['id']
        assert i['sck'] == sck
        assert scsn == 2 ** 48 - 1
        assert message['id'] == r1['id']

        # Send relay message: initiator --> responder
        await initiator.send(pack_nonce(i['rcck'], i['id'], r1['id'], i['rccsn']), {
            'type': 'rawr',
        }, box=None)

        # Receive relay message: initiator --> responder
        message, _, ck, s, d, csn = await first_responder.recv(box=None)
        assert ck == i['rcck']
        assert s == i['id']
        assert d == r1['id']
        assert csn == i['rccsn']
        assert message['type'] == 'rawr'

        # Connect a new responder
        second_responder, r = await client_factory(responder_handshake=True)

        # Expect protocol error
        await connection_closed_future()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.protocol_error

        # Bye
        await first_responder.close()
        await second_responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_path_full_lite(self, initiator_key, server, client_factory):
        """
        Add 253 fake responders to a path. Then, add a 254th responder
        and check that the correct error code (Path Full) is being
        returned.
        """
        assert len(server.protocols) == 0

        # Get path instance of server
        path = server.paths.get(initiator_key.pk)

        # Add fake clients to path
        clients = [_FakePathClient() for _ in range(0x02, 0x100)]
        for client in clients:
            path.add_responder(client)

        # Now the path is full
        with pytest.raises(websockets.ConnectionClosed) as exc_info:
            await client_factory(responder_handshake=True)
        assert exc_info.value.code == CloseCode.path_full_error

        # Remove fake clients from path
        for client in clients:
            path.remove_client(client)
        await server.wait_connections_closed()

    @pytest.saltyrtc.long_test
    @pytest.mark.asyncio
    async def test_path_full(self, event_loop, server, client_factory):
        """
        Add 253 responders to a path. Then, add a 254th responder
        and check that the correct error code (Path Full) is being
        returned.
        """
        assert len(server.protocols) == 0

        tasks = [client_factory(responder_handshake=True, timeout=20.0)
                 for _ in range(0x02, 0x100)]
        clients = await asyncio.gather(*tasks, loop=event_loop)

        # All clients must be open
        assert all((client.ws_client.open for client, _ in clients))

        # Now the path is full
        with pytest.raises(websockets.ConnectionClosed) as exc_info:
            await client_factory(responder_handshake=True)
        assert exc_info.value.code == CloseCode.path_full_error

        # Close all clients
        tasks = [client.close() for client, _ in clients]
        await asyncio.gather(*tasks, loop=event_loop)
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_explicit_permanent_key_unavailable(
            self, server_no_key, server, client_factory
    ):
        """
        Check that the server rejects a permanent key if the server
        has none.
        """
        key = libnacl.public.SecretKey()

        # Expect invalid key
        with pytest.raises(websockets.ConnectionClosed) as exc_info:
            await client_factory(
                server=server_no_key, permanent_key=key.pk, explicit_permanent_key=True,
                initiator_handshake=True)
        assert exc_info.value.code == CloseCode.invalid_key
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_explicit_invalid_permanent_key(
            self, server, client_factory
    ):
        """
        Check that the server rejects a permanent key it doesn't have.
        """
        key = libnacl.public.SecretKey()

        # Expect invalid key
        with pytest.raises(websockets.ConnectionClosed) as exc_info:
            await client_factory(
                permanent_key=key.pk, explicit_permanent_key=True,
                initiator_handshake=True)
        assert exc_info.value.code == CloseCode.invalid_key
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_explicit_permanent_key(
            self, server, client_factory, initiator_key, responder_key,
            server_permanent_keys
    ):
        """
        Check that explicitly requesting a permanent key works as
        intended.
        """
        for key in server_permanent_keys:
            # Initiator handshake
            initiator, i = await client_factory(
                permanent_key=key.pk, explicit_permanent_key=True,
                initiator_handshake=True)
            assert len(i['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
            signed_keys = initiator.sign_box.decrypt(
                i['signed_keys'], nonce=i['nonces']['server-auth'])
            assert signed_keys == i['ssk'] + initiator_key.pk
            await initiator.close()

            # Responder handshake
            responder, r = await client_factory(responder_handshake=True)
            assert len(r['signed_keys']) == SIGNED_KEYS_CIPHERTEXT_LENGTH
            signed_keys = responder.sign_box.decrypt(
                r['signed_keys'], nonce=r['nonces']['server-auth'])
            assert signed_keys == r['ssk'] + responder_key.pk
            await responder.close()
            await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_initiator_disconnected(self, server, client_factory):
        """
        Check that the server sends a 'disconnected' message to all
        responders of the associated path when the initiator
        disconnects.
        """
        # Client handshakes
        initiator, i = await client_factory(initiator_handshake=True)
        responder1, _ = await client_factory(responder_handshake=True)
        responder2, _ = await client_factory(responder_handshake=True)

        # Disconnect initiator
        await initiator.close()

        # Expect 'disconnected' messages sent to all responders
        msg1, *_ = await responder1.recv()
        msg2, *_ = await responder2.recv()
        assert msg1 == msg2 == {'type': 'disconnected', 'id': i['id']}

        await responder1.close()
        await responder2.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_responder_disconnected(self, server, client_factory):
        """
        Check that the server sends 'disconnected' message to the
        initiator when a responder disconnects.
        """
        # Client handshakes
        responder, r = await client_factory(responder_handshake=True)
        initiator, i = await client_factory(initiator_handshake=True)

        # Disconnect initiator
        await responder.close()

        # Expect 'disconnected' message sent to initiator
        msg, *_ = await initiator.recv()
        assert msg == {'type': 'disconnected', 'id': r['id']}

        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_drop_responder_no_disconnect(
            self, pack_nonce, server, client_factory
    ):
        """
        Ensure that dropping a responder explicitly does not trigger a
        'disconnected' message being sent to the initiator.
        """
        # Client handshakes
        initiator, i = await client_factory(initiator_handshake=True)
        responder, r = await client_factory(responder_handshake=True)

        # Ignore 'new-responder' message
        message, *_ = await initiator.recv()
        assert message['type'] == 'new-responder'

        # Drop responder
        await initiator.send(pack_nonce(i['cck'], 0x01, 0x00, i['ccsn']), {
            'type': 'drop-responder',
            'id': r['id'],
        })

        # Ensure no further message is being received
        with pytest.raises(asyncio.TimeoutError):
            await initiator.recv(timeout=1.0)

        # Bye
        await initiator.close()
        await server.wait_connections_closed()
