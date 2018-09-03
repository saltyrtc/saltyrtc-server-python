"""
The tests provided in this module make sure that the server
instance behaves as expected.
"""
import asyncio
import collections

import libnacl.public
import pytest

from saltyrtc.server import (
    exception,
    serve,
)
from saltyrtc.server.events import Event


class TestServer:
    @pytest.mark.asyncio
    def test_repeated_permanent_keys(self, server_permanent_keys):
        """
        Ensure the server does not accept repeated keys.
        """
        keys = server_permanent_keys + [server_permanent_keys[1]]
        with pytest.raises(exception.ServerKeyError) as exc_info:
            yield from serve(None, keys)
        assert 'Repeated permanent keys' in str(exc_info.value)

    @pytest.mark.asyncio
    def test_event_emitted(
            self, initiator_key, responder_key, cookie_factory, server, client_factory
    ):
        """
        Ensure the server does emit events as expected.
        """
        # Dictionary where fired events are added
        events_fired = collections.defaultdict(list)

        @asyncio.coroutine
        def callback(event: Event, *data):
            events_fired[event].append(data)

        # Register event callback for all events
        for event in Event:
            server.register_event_callback(event, callback)

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

        yield from initiator.recv()
        assert set(events_fired.keys()) == {
            Event.initiator_connected,
            Event.responder_connected,
        }
        assert events_fired[Event.initiator_connected] == [
            (initiator_key.hex_pk().decode('ascii'),)
        ]
        assert events_fired[Event.responder_connected] == [
            (initiator_key.hex_pk().decode('ascii'),)
        ]

        yield from initiator.close()
        yield from responder.close()
        yield from server.wait_connections_closed()

        assert set(events_fired.keys()) == {
            Event.initiator_connected,
            Event.responder_connected,
            Event.disconnected,
        }
        assert events_fired[Event.disconnected] == [
            (initiator_key.hex_pk().decode('ascii'), 1000),
            (initiator_key.hex_pk().decode('ascii'), 1000),
        ]
