"""
The tests provided in this module make sure that the server
instance behaves as expected.
"""
import asyncio
import collections

import pytest

from saltyrtc.server import (
    AddressType,
    CloseCode,
    RawMessage,
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
            self, mocker, log_ignore_filter, log_handler, sleep, server, client_factory,
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
        initiator, _ = yield from client_factory(initiator_handshake=True)

        # Expect internal error
        yield from server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.internal_error
        assert len([record for record in log_handler.records
                    if 'returned unexpectedly' in record.message]) == 2

    @pytest.mark.asyncio
    def test_task_cancelled_connection_open(
            self, mocker, log_ignore_filter, log_handler, sleep, server, client_factory
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
        initiator, _ = yield from client_factory(initiator_handshake=True)

        # Expect internal error
        yield from server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.internal_error
        assert len([record for record in log_handler.records
                    if 'has been cancelled' in record.message]) == 2

    @pytest.mark.asyncio
    def test_task_returned_connection_closed(
            self, mocker, event_loop, log_handler, sleep, server, client_factory
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
        initiator, _ = yield from client_factory(initiator_handshake=True)

        # Wait for the receive loop to return (and the waiter it returns)
        yield from (yield from receive_loop_closed_future)

        # Bye
        yield from initiator.ws_client.close()
        yield from server.wait_connections_closed()
        partials = ('Task done', 'result=None')
        assert len([record for record in log_handler.records
                    if all(partial in record.message for partial in partials)]) == 1

    @pytest.mark.asyncio
    def test_disconnect_during_receive(
            self, mocker, log_handler, sleep, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when the
        receive loop returns.
        """
        # Mock the initiator keep alive loop to stay quiet
        class _MockProtocol(ServerProtocol):
            @asyncio.coroutine
            def keep_alive_loop(self):
                yield from sleep(float('inf'))

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake & disconnect immediately
        initiator, _ = yield from client_factory(initiator_handshake=True)
        yield from initiator.ws_client.close()

        # Expect disconnect during receive in the log
        yield from server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while receiving' in record.message]) == 1

    @pytest.mark.asyncio
    def test_disconnect_during_send(
            self, mocker, event_loop, log_handler, ws_client_factory, server
    ):
        """
        Check that the server handles a disconnect correctly when the
        server tries to send something while the client is already gone.
        """
        close_future = asyncio.Future(loop=event_loop)

        # Mock the handshake to wait until the client has been closed
        class _MockProtocol(ServerProtocol):
            @asyncio.coroutine
            def handshake(self):
                yield from close_future
                return (yield from super().handshake())

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Connect & disconnect immediately
        ws_client = yield from ws_client_factory()
        yield from ws_client.close()
        close_future.set_result(None)

        # Expect disconnect during send in the log
        yield from server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while sending' in record.message]) == 1

    @pytest.mark.asyncio
    def test_disconnect_during_task(
            self, mocker, event_loop, log_handler, sleep, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when a
        task (that awaits a send operation) is awaited.
        """
        close_future = asyncio.Future(loop=event_loop)

        # Mock the loops to stay quiet and enqueue a relay task
        class _MockProtocol(ServerProtocol):
            @asyncio.coroutine
            def initiator_receive_loop(self):
                yield from close_future

                @asyncio.coroutine
                def _send_task():
                    message = RawMessage(AddressType.server, self.client.id, b'\x00')
                    message._nonce = b'\x00' * 24
                    yield from self.client.send(message)

                yield from self.client.enqueue_task(_send_task())
                yield from sleep(float('inf'))

            @asyncio.coroutine
            def keep_alive_loop(self):
                yield from sleep(float('inf'))

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake & disconnect immediately
        initiator, _ = yield from client_factory(initiator_handshake=True)
        yield from initiator.ws_client.close()
        close_future.set_result(None)

        # Expect disconnect during send in the log
        yield from server.wait_connections_closed()
        partials = ['closed while sending', 'Stopping active task', 'Task done']
        assert len([record for record in log_handler.records
                    if any(partial in record.message for partial in partials)]) == 3

    @pytest.mark.asyncio
    def test_disconnect_keep_alive_ping(
            self, mocker, event_loop, log_handler, sleep, ws_client_factory,
            initiator_key, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when
        sending a ping.
        """
        # Mock the initiator receive loop to return after a brief timeout
        class _MockProtocol(ServerProtocol):
            @asyncio.coroutine
            def initiator_receive_loop(self):
                # Wait until closed (and a little further)
                yield from self.client.connection_closed_future
                yield from sleep(0.1)

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Connect client to server
        ws_client = yield from ws_client_factory()

        # Patch server's keep alive interval and timeout
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client._keep_alive_interval = 0.1

        # Initiator handshake
        yield from client_factory(ws_client=ws_client, initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Get path instance of server and initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_initiator()

        # Delay sending a ping
        ping = path_client._connection.ping
        ready_future = asyncio.Future(loop=event_loop)

        @asyncio.coroutine
        def _mock_ping(*args):
            yield from ready_future
            return (yield from ping(*args))

        mocker.patch.object(path_client._connection, 'ping', _mock_ping)

        # Let the server know we're ready once the connection has been closed.
        # The server will now try to send a ping.
        yield from ws_client.close()
        ready_future.set_result(None)

        # Expect a normal closure (seen on the server side)
        close_code = yield from connection_closed_future()
        assert close_code == 1000
        yield from server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while pinging' in record.message]) == 1

    @pytest.mark.asyncio
    def test_disconnect_keep_alive_pong(
            self, mocker, sleep, log_handler, ws_client_factory, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when
        waiting for a pong.
        """
        # Mock the initiator receive loop to return after a brief timeout
        class _MockProtocol(ServerProtocol):
            @asyncio.coroutine
            def initiator_receive_loop(self):
                # Wait until closed
                yield from self.client.connection_closed_future

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Create client and patch it to not answer pings
        ws_client = yield from ws_client_factory()
        ws_client.pong = asyncio.coroutine(lambda *args, **kwargs: None)

        # Patch server's keep alive interval and timeout
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client._keep_alive_interval = 0.1
        protocol.client.keep_alive_timeout = float('inf')

        # Initiator handshake
        yield from client_factory(ws_client=ws_client, initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Ensure the server can send a ping before closing
        yield from sleep(0.25)
        yield from ws_client.close()

        # Expect a normal closure (seen on the server side)
        close_code = yield from connection_closed_future()
        assert close_code == 1000
        yield from server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while waiting for pong' in record.message]) == 1

    @pytest.mark.asyncio
    def test_misbehaving_task(
            self, mocker, sleep, log_ignore_filter, log_handler, initiator_key, server,
            client_factory
    ):
        """
        Check that the server handles a misbehaving task correctly.
        """
        log_ignore_filter(lambda record: 'queue did not close' in record.message)

        # Initiator handshake
        initiator, _ = yield from client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Mock the task queue join timeout
        mocker.patch('saltyrtc.server.server._TASK_QUEUE_JOIN_TIMEOUT', 0.1)

        # Get path instance of server and initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_initiator()

        @asyncio.coroutine
        def bad_task():
            try:
                yield from sleep(float('inf'))
            except asyncio.CancelledError:
                yield from sleep(float('inf'))

        yield from path_client.enqueue_task(bad_task())

        # Close and wait
        yield from initiator.ws_client.close()

        # Expect a normal closure (seen on the server side)
        close_code = yield from connection_closed_future()
        assert close_code == 1000
        yield from server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'queue did not close' in record.message]) == 1

    @pytest.mark.asyncio
    def test_event_emitted(self, initiator_key, server, client_factory):
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
        initiator, _ = yield from client_factory(initiator_handshake=True)

        # Responder handshake
        responder, _ = yield from client_factory(responder_handshake=True)

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
