"""
The tests provided in this module make sure that the server
instance behaves as expected.
"""
import asyncio
import collections

import libnacl.public
import pytest

from saltyrtc.server import (
    CloseCode,
    ServerProtocol,
    exception,
    serve,
)
from saltyrtc.server.events import Event


@pytest.mark.usefixtures('evaluate_log')
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
    def test_task_returned_connection_open(
            self, mocker, log_ignore_filter, sleep, cookie_factory, server,
            client_factory,
    ):
        """
        Ensure the server handles a task returning early while the
        connection is still running.
        """
        log_ignore_filter(lambda record: 'returned unexpectedly' in record.message)

        # Mock the initiator receive loop to return after a brief timeout
        class _MockProtocol(ServerProtocol):
            @asyncio.coroutine
            def initiator_receive_loop(self):
                # ZZzzzZZzz
                yield from sleep(0.1)

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 1337
        i['rcck'] = cookie_factory()

        # Expect internal error
        yield from server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.internal_error

    @pytest.mark.asyncio
    def test_task_cancelled_connection_open(
            self, mocker, log_ignore_filter, sleep, cookie_factory, server,
            client_factory
    ):
        """
        Ensure the server handles a task being cancelled early while
        the connection is still running.
        """
        ignore = 'has been cancelled'
        log_ignore_filter(lambda record: ignore in record.message)

        # Mock the initiator receive loop and cancel itself after a brief timeout
        class _MockProtocol(ServerProtocol):
            def initiator_receive_loop(self):
                receive_loop = asyncio.ensure_future(
                    super().initiator_receive_loop(), loop=self._loop)

                @asyncio.coroutine
                def _cancel_loop():
                    yield from sleep(0.1)
                    receive_loop.cancel()

                asyncio.ensure_future(_cancel_loop(), loop=self._loop)
                return receive_loop

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 1337
        i['rcck'] = cookie_factory()

        # Expect internal error
        yield from server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.internal_error

    @pytest.mark.asyncio
    def test_task_returned_connection_closed(
            self, mocker, event_loop, sleep, cookie_factory, server, client_factory
    ):
        """
        Ensure the server does gracefully handle a task returning when
        the connection is already closed.
        """
        # Mock the initiator receive loop to be able to notify when it returns
        receive_loop_closed_future = asyncio.Future(loop=event_loop)

        class _MockProtocol(ServerProtocol):
            @asyncio.coroutine
            def initiator_receive_loop(self):
                connection_closed_future = self.client._connection_closed_future
                self.client._connection_closed_future = asyncio.Future(loop=self._loop)

                # ZZzzzZZzz
                yield from sleep(0.1)

                # Replace the future with the previous one to prevent an exception
                @asyncio.coroutine
                def _revert_future():
                    yield from sleep(0.05)
                    self.client._connection_closed_future = connection_closed_future
                asyncio.ensure_future(_revert_future(), loop=self._loop)

                # Resolve the connection closed future and the loop future
                self.client._connection_closed_future.set_result(1337)
                receive_loop_closed_future.set_result(sleep(0.1))

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, i = yield from client_factory(initiator_handshake=True)
        i['rccsn'] = 1337
        i['rcck'] = cookie_factory()

        # Wait for the receive loop to return (and the waiter it returns)
        yield from (yield from receive_loop_closed_future)

        # Bye
        yield from initiator.ws_client.close()
        yield from server.wait_connections_closed()

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
