"""
The tests provided in this module make sure that the server
instance behaves as expected.
"""
import asyncio
import collections

import pytest

from saltyrtc.server import (
    SERVER_ADDRESS,
    CloseCode,
    PathClient,
    RelayMessage,
    ServerProtocol,
    exception,
    serve,
)
from saltyrtc.server.events import Event


@pytest.mark.usefixtures('evaluate_log')
class TestServer:
    @pytest.mark.asyncio
    async def test_repeated_permanent_keys(self, server_permanent_keys):
        """
        Ensure the server does not accept repeated keys.
        """
        keys = server_permanent_keys + [server_permanent_keys[1]]
        with pytest.raises(exception.ServerKeyError) as exc_info:
            await serve(None, keys)
        assert 'Repeated permanent keys' in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_task_returned_connection_open(
            self, mocker, log_ignore_filter, log_handler, sleep, server, client_factory,
    ):
        """
        Ensure the server handles a task returning early while the
        connection is still running.
        """
        def _filter(record):
            return 'returned unexpectedly' in record.message \
                   or (record.exception_message is not None
                       and 'returned unexpectedly' in record.exception_message)
        log_ignore_filter(_filter)

        # Mock the initiator receive loop to return after a brief timeout
        class _MockProtocol(ServerProtocol):
            async def initiator_receive_loop(self):
                # ZZzzzZZzz
                await sleep(0.1)

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, _ = await client_factory(initiator_handshake=True)

        # Expect internal error
        await server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.internal_error
        assert len([record for record in log_handler.records if _filter(record)]) == 1

    @pytest.mark.asyncio
    async def test_tasks_cancelled_connection_open(
            self, mocker, log_ignore_filter, log_handler, sleep, server, client_factory
    ):
        """
        Ensure the server handles all tasks being cancelled early while
        the connection is still running.
        """
        def _filter(record):
            return 'All tasks have been cancelled' in record.message \
                   or (record.exception_message is not None
                       and 'All tasks have been cancelled' in record.exception_message)
        log_ignore_filter(_filter)

        async def _cancel_task(task):
            await sleep(0.05)
            task.cancel()

        # Mock the initiator receive loop and keep-alive loop.
        # Cancel them after a brief timeout.
        class _MockProtocol(ServerProtocol):
            async def initiator_receive_loop(self):
                receive_loop = self._loop.create_task(super().initiator_receive_loop())
                self._loop.create_task(_cancel_task(receive_loop))
                await receive_loop

            async def keep_alive_loop(self):
                keep_alive_loop = self._loop.create_task(super().keep_alive_loop())
                self._loop.create_task(_cancel_task(keep_alive_loop))
                await keep_alive_loop

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, _ = await client_factory(initiator_handshake=True)

        # Expect internal error
        await server.wait_connections_closed()
        assert not initiator.ws_client.open
        assert initiator.ws_client.close_code == CloseCode.internal_error
        assert len([record for record in log_handler.records if _filter(record)]) == 1

    @pytest.mark.asyncio
    async def test_disconnect_during_receive(
            self, mocker, log_handler, sleep, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when the
        receive loop returns.
        """
        # Mock the initiator keep alive loop to stay quiet
        class _MockProtocol(ServerProtocol):
            async def keep_alive_loop(self):
                await sleep(60.0)

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake & disconnect immediately
        initiator, _ = await client_factory(initiator_handshake=True)
        await initiator.ws_client.close()

        # Expect disconnect during receive in the log
        await server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while receiving' in record.message]) == 1

    @pytest.mark.asyncio
    async def test_disconnect_during_send(
            self, mocker, event_loop, log_handler, ws_client_factory, server
    ):
        """
        Check that the server handles a disconnect correctly when the
        server tries to send something while the client is already gone.
        """
        close_future = asyncio.Future(loop=event_loop)

        # Mock the handshake to wait until the client has been closed
        class _MockProtocol(ServerProtocol):
            async def handshake(self):
                await close_future
                return await super().handshake()

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Connect & disconnect immediately
        ws_client = await ws_client_factory()
        await ws_client.close()
        close_future.set_result(None)

        # Expect disconnect during send in the log
        await server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while sending' in record.message]) == 1

    @pytest.mark.asyncio
    async def test_disconnect_during_task(
            self, mocker, event_loop, log_handler, sleep, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when a
        job (that awaits a send operation) is awaited.
        """
        close_future = asyncio.Future(loop=event_loop)

        # Mock the loops to stay quiet and enqueue a relay job
        class _MockProtocol(ServerProtocol):
            async def initiator_receive_loop(self):
                await close_future

                async def _send_job():
                    message = RelayMessage(
                        SERVER_ADDRESS, self.client.id, b'\x00', b'\x00' * 24)
                    await self.client.send(message)

                await self.client.jobs.enqueue(_send_job())
                await sleep(60.0)

            async def keep_alive_loop(self):
                await sleep(60.0)

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake & disconnect immediately
        initiator, _ = await client_factory(initiator_handshake=True)
        await initiator.ws_client.close()
        close_future.set_result(None)

        # Expect disconnect during send in the log
        await server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while sending' in record.message]) == 1
        assert len([record for record in log_handler.records
                    if 'Job returned due to connection closed (code: 1000)'
                    in record.message]) == 1
        assert len([record for record in log_handler.records
                    if 'Task was cancelled' in record.message]) == 2

    @pytest.mark.asyncio
    async def test_disconnect_keep_alive_ping(
            self, mocker, event_loop, log_handler, sleep, ws_client_factory,
            initiator_key, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when
        sending a ping.
        """
        # Mock the initiator receive loop to return after a brief timeout
        class _MockProtocol(ServerProtocol):
            async def initiator_receive_loop(self):
                # Wait until closed (and a little further)
                result = await self.client.connection_closed_future
                await sleep(0.1)
                raise result

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Connect client to server
        ws_client = await ws_client_factory()

        # Patch server's keep alive interval and timeout
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client._keep_alive_interval = 0.1

        # Initiator handshake
        await client_factory(ws_client=ws_client, initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Get path instance of server and initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_initiator()

        # Delay sending a ping
        ping = path_client._connection.ping
        ready_future = asyncio.Future(loop=event_loop)

        async def _mock_ping(*args):
            await ready_future
            return await ping(*args)

        mocker.patch.object(path_client._connection, 'ping', _mock_ping)

        # Let the server know we're ready once the connection has been closed.
        # The server will now try to send a ping.
        await ws_client.close()
        ready_future.set_result(None)

        # Expect a normal closure (seen on the server side)
        disconnected = await connection_closed_future()
        assert disconnected.reason == 1000
        await server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while pinging' in record.message]) == 1

    @pytest.mark.asyncio
    async def test_disconnect_keep_alive_pong(
            self, mocker, sleep, log_handler, ws_client_factory, server, client_factory
    ):
        """
        Check that the server handles a disconnect correctly when
        waiting for a pong.
        """
        # Mock the initiator receive loop to return after a brief timeout
        class _MockProtocol(ServerProtocol):
            async def initiator_receive_loop(self):
                # Wait until closed
                raise await self.client.connection_closed_future

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Create client and patch it to not answer pings
        ws_client = await ws_client_factory()
        ws_client.pong = asyncio.coroutine(lambda *args, **kwargs: None)

        # Patch server's keep alive interval and timeout
        assert len(server.protocols) == 1
        protocol = next(iter(server.protocols))
        protocol.client._keep_alive_interval = 0.1
        protocol.client.keep_alive_timeout = 60.0

        # Initiator handshake
        await client_factory(ws_client=ws_client, initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Ensure the server can send a ping before closing
        await sleep(0.25)
        await ws_client.close()

        # Expect a normal closure (seen on the server side)
        disconnected = await connection_closed_future()
        assert disconnected.reason == 1000
        await server.wait_connections_closed()
        assert len([record for record in log_handler.records
                    if 'closed while waiting for pong' in record.message]) == 1

    @pytest.mark.asyncio
    async def test_cancelled_job(
            self, event_loop, sleep, log_handler, initiator_key, server, client_factory
    ):
        """
        Check that the server handles a cancelled job correctly.
        """
        # Initiator handshake
        initiator, _ = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Get path instance of server and initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_initiator()

        # Enqueue task and cancel immediately
        job = event_loop.create_task(sleep(60.0))
        await path_client.jobs.enqueue(job)
        job.cancel()

        async def coroutine(future_):
            await future_

        # Enqueue coroutine waiting for a future and cancel the future
        # immediately.
        future = asyncio.Future(loop=event_loop)
        await path_client.jobs.enqueue(coroutine(future))
        future.cancel()

        # Close on the job queue
        await path_client.jobs.enqueue(initiator.close())

        # Enqueue task and cancel immediately
        job = event_loop.create_task(sleep(60.0))
        await path_client.jobs.enqueue(job)
        job.cancel()

        # Enqueue coroutine waiting for a future and cancel the future
        # immediately.
        future = asyncio.Future(loop=event_loop)
        await path_client.jobs.enqueue(coroutine(future))
        future.cancel()

        # Expect a normal closure (seen on the server side)
        disconnected = await connection_closed_future()
        assert disconnected.reason == 1000
        await server.wait_connections_closed()

        # Ensure the job has been picked up as cancelled
        # Note: Either 2 or 3 depending on whether the `.close` is marked as done before
        #       the ConnectionClosed exception is being dispatched or afterwards.
        assert len([record for record in log_handler.records
                    if 'Active job cancelled' in record.message]) in {2, 3}
        assert len([record for record in log_handler.records
                    if 'Already cancelled task' in record.message]) == 1
        assert len([record for record in log_handler.records
                    if 'Closing coroutine' in record.message]) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize('raise_2nd_cancel', [0, 1])
    async def test_misbehaving_coroutine(
            self, mocker, event_loop, sleep, log_ignore_filter, log_handler,
            initiator_key, server, client_factory, raise_2nd_cancel
    ):
        """
        Check that the server handles a misbehaving coroutine
        correctly.
        """
        log_ignore_filter(lambda record: 'queue did not complete' in record.message)

        # Initiator handshake
        initiator, _ = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Mock the job queue join timeout
        mocker.patch('saltyrtc.server.server._JOB_QUEUE_JOIN_TIMEOUT', 0.1)

        # Get path instance of server and initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_initiator()

        async def bad_coroutine(future):
            # Ignore first cancellation
            try:
                await sleep(60.0)
            except asyncio.CancelledError:
                future.set_result(None)

            # Ignore second cancellation (due to the .join() operation timing out, which
            # cancels the job queue runner and thus cancels the currently awaited job,
            # which is this job).
            try:
                await sleep(60.0)
            except asyncio.CancelledError:
                if raise_2nd_cancel:
                    raise

        async def enqueue_bad_coroutine():
            future = asyncio.Future(loop=event_loop)
            await path_client.jobs.enqueue(bad_coroutine(future))
            return future

        # Enqueue misbehaving coroutine
        # Note: We need to add two of these since one of them will be dequeued
        #       immediately and waited for which runs in a different code
        #       section.
        active_coroutine_future = await enqueue_bad_coroutine()
        queued_coroutine_future = await enqueue_bad_coroutine()

        # Close and wait
        await initiator.ws_client.close()

        # Expect a normal closure (seen on the server side)
        disconnected = await connection_closed_future()
        assert disconnected.reason == 1000
        await server.wait_connections_closed()

        # The active coroutine was activated and thus will be cancelled
        assert active_coroutine_future.result() is None

        # The active coroutine's cancellation will only be picked up by the job queue
        # runner in case a cancellation is ignored more than once.
        #
        # Note: The first cancellation is obvious and can be traced back to the
        #       cancellation of the job queue.
        #       The second cancellation happens due to the .join() operation timeout
        #       being cancelled. The job queue runner is being cancelled and thus the
        #       currently awaited job will be cancelled as well.
        assert len([record for record in log_handler.records
                    if 'Active job cancelled' in record.message]) == raise_2nd_cancel

        # The queued coroutine was never waited for and it has not been added as a task
        # to the event loop either. Thus, it will not be cancelled.
        assert not queued_coroutine_future.done()
        # The queued jobs will be cancelled.
        assert len([record for record in log_handler.records
                    if 'Cancelling 2 queued jobs' in record.message]) == 1
        # Ensure it has been picked up as a coroutine
        assert len([record for record in log_handler.records
                    if 'Closing coroutine' in record.message]) == 1

        # Check log messages
        assert len([record for record in log_handler.records
                    if 'queue did not complete' in record.message]) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize('raise_2nd_cancel', [0, 1])
    async def test_misbehaving_task(
            self, mocker, event_loop, sleep, log_ignore_filter, log_handler,
            initiator_key, server, client_factory, raise_2nd_cancel
    ):
        """
        Check that the server handles a misbehaving task correctly.
        """
        log_ignore_filter(lambda record: 'queue did not complete' in record.message)

        # Initiator handshake
        initiator, _ = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Mock the job queue join timeout
        mocker.patch('saltyrtc.server.server._JOB_QUEUE_JOIN_TIMEOUT', 0.1)

        # Get path instance of server and initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_initiator()

        async def bad_coroutine(future, first):
            # Ignore first cancellation
            try:
                await sleep(60.0)
            except asyncio.CancelledError:
                future.set_result(None)

            # Ignore second cancellation (due to the .join() operation timing out, which
            # cancels the job queue runner and thus cancels the currently awaited job,
            # which is this job).
            if first:
                try:
                    await sleep(60.0)
                except asyncio.CancelledError:
                    if raise_2nd_cancel:
                        raise

        async def enqueue_bad_task(first):
            future = asyncio.Future(loop=event_loop)
            await path_client.jobs.enqueue(
                event_loop.create_task(bad_coroutine(future, first)))
            return future

        # Enqueue misbehaving task
        # Note: We need to add two of these since one of them will be dequeued
        #       immediately and waited for which runs in a different code
        #       section.
        active_task_future = await enqueue_bad_task(True)
        queued_task_future = await enqueue_bad_task(False)

        # Close and wait
        await initiator.ws_client.close()

        # Expect a normal closure (seen on the server side)
        disconnected = await connection_closed_future()
        assert disconnected.reason == 1000
        await server.wait_connections_closed()

        # The active job will be implicitly cancelled by cancellation of the job queue
        # runner.
        assert active_task_future.result() is None

        # The active task's cancellation will only be picked up by the job queue
        # runner in case a cancellation is ignored more than once.
        #
        # Note: The first cancellation is obvious and can be traced back to the
        #       cancellation of the job queue.
        #       The second cancellation happens due to the .join() operation timeout
        #       being cancelled. The job queue runner is being cancelled and thus the
        #       currently awaited job will be cancelled as well.
        assert len([record for record in log_handler.records
                    if 'Active job cancelled' in record.message]) == raise_2nd_cancel

        # The queued jobs have been scheduled on the event loop and thus will be
        # cancelled by the job queue cancellation.
        assert queued_task_future.result() is None
        # The queued job will be cancelled.
        assert len([record for record in log_handler.records
                    if 'Cancelling 2 queued jobs' in record.message]) == 1
        # Ensure it has been picked up as a task
        assert len([record for record in log_handler.records
                    if 'Cancelling task' in record.message]) == 2

        # Check log messages
        assert len([record for record in log_handler.records
                    if 'queue did not complete' in record.message]) == 1

    @pytest.mark.asyncio
    async def test_event_emitted(self, initiator_key, server, client_factory):
        """
        Ensure the server does emit events as expected.
        """
        # Dictionary where fired events are added
        events_fired = collections.defaultdict(list)

        async def callback(event: Event, *data):
            events_fired[event].append(data)

        # Register event callback for all events
        for event in Event:
            server.register_event_callback(event, callback)

        # Initiator handshake
        initiator, _ = await client_factory(initiator_handshake=True)

        # Responder handshake
        responder, _ = await client_factory(responder_handshake=True)

        await initiator.recv()
        assert set(events_fired.keys()) == {
            Event.initiator_connected,
            Event.responder_connected,
        }
        assert events_fired[Event.initiator_connected] == [
            (initiator_key.hex_pk().decode('ascii'), None)
        ]
        assert events_fired[Event.responder_connected] == [
            (initiator_key.hex_pk().decode('ascii'), None)
        ]

        await initiator.close()
        await responder.close()
        await server.wait_connections_closed()

        assert set(events_fired.keys()) == {
            Event.initiator_connected,
            Event.responder_connected,
            Event.disconnected,
        }
        assert events_fired[Event.disconnected] == [
            (initiator_key.hex_pk().decode('ascii'), 1000),
            (initiator_key.hex_pk().decode('ascii'), 1000),
        ]

    @pytest.mark.asyncio
    async def test_error_after_disconnect(self, mocker, server, client_factory):
        """
        Ensure the server does not error after the client's disconnect
        procedure has been started.

        This test exists to prevent a regression. Previously it was
        possible to enqueue jobs on a client whose job queue has
        already been closed.
        """
        # Initiator handshake
        initiator, _ = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Mock the responder's client handler to wait before raising an exception
        class _MockProtocol(ServerProtocol):
            async def handle_client(self):
                try:
                    await super().handle_client()
                except Exception:
                    # Hold back the exception until the initiator has closed its
                    # connection to provoke a race condition
                    await connection_closed_future()
                    raise

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Responder handshake
        responder, _ = await client_factory(responder_handshake=True)

        # Disconnect the responder first, then the initiator.
        # The initiator may trigger some behaviour on the responder resulting in an
        # exception being logged. Thus, we don't have to assert anything here.
        await responder.close()
        await initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_drop_client_while_authenticating(
            self, mocker, event_loop, server, client_factory
    ):
        """
        Ensure the server handles closing the job queue correctly
        when a client is being dropped by another client after it has
        been added to a path but before the handshake completed.
        """
        # Mock the client's send method to wait a little longer after having sent a
        # 'server-auth' message. This simulates a 'server-auth' send taking a little
        # longer.
        client_dropped_future = \
            asyncio.Future(loop=event_loop)  # type: asyncio.Future[None]

        class _MockProtocol(ServerProtocol):
            async def handshake(self) -> None:
                await super().handshake()
                await client_dropped_future

            def _drop_client(self, client: PathClient, code: CloseCode) -> None:
                super()._drop_client(client, code)
                client_dropped_future.set_result(None)

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # First initiator handshake
        first_initiator, _ = await client_factory(initiator_handshake=True)
        connection_closed_future = server.wait_connection_closed_marker()

        # Second initiator handshake (drops the first initiator)
        second_initiator, _ = await client_factory(initiator_handshake=True)

        # Wait until the first initiator has been dropped
        await connection_closed_future()
        await second_initiator.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_cancellation_active(
            self, mocker, event_loop, sleep, pack_nonce, cookie_factory, server,
            client_factory, initiator_key
    ):
        """
        Ensure the server detects cancellation of itself when running a
        relay task.

        In this case, the relay task of the initiator is the currently
        active job of the responder.
        """
        sending_in_progress_future = asyncio.Future(loop=event_loop)
        cancelled_future = asyncio.Future(loop=event_loop)

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 23
        r['icck'] = cookie_factory()

        class _MockProtocol(ServerProtocol):
            async def keep_alive_loop(self):
                await sending_in_progress_future
                raise exception.PingTimeoutError('Meh!')

            async def initiator_receive_loop(self):
                try:
                    return await super().initiator_receive_loop()
                except asyncio.CancelledError:
                    cancelled_future.set_result(None)
                    raise

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 98798981
        i['rcck'] = cookie_factory()

        # new-initiator
        await responder.recv()

        # Get initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_responder(r['id'])
        _send = path_client._connection.send

        # Mock responder instance: Block forwarding on send
        async def _mock_send(*_):
            mocker.patch.object(path_client._connection, 'send', _send)
            await sleep(0.1)
            sending_in_progress_future.set_result(None)
            await sleep(5.0)
            cancelled_future.set_exception(asyncio.TimeoutError())

        mocker.patch.object(path_client._connection, 'send', _mock_send)

        # Send a relay message: initiator --> responder
        nonce = pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn'])
        await initiator.send(nonce, b'\xfe' * 2**15, box=None)
        i['ccsn'] += 1

        # Wait for the sending procedure to be started, then wait for the keep-alive loop
        # to time out.
        await sending_in_progress_future

        # Expect the initiator's receive loop to be cancelled
        await cancelled_future

        # Responder: Receive 'disconnected' message
        message, *_ = await responder.recv()
        assert message == {'type': 'disconnected', 'id': i['id']}

        # Bye
        await responder.close()
        await server.wait_connections_closed()

    @pytest.mark.asyncio
    async def test_relay_cancellation_queued(
            self, mocker, event_loop, sleep, pack_nonce, cookie_factory, server,
            client_factory, initiator_key
    ):
        """
        Ensure the server detects cancellation of itself when running a
        relay task.

        In this case, the relay task of the initiator is a queued job
        for the responder.
        """
        sending_in_progress_future = asyncio.Future(loop=event_loop)
        cancelled_future = asyncio.Future(loop=event_loop)

        # Responder handshake
        responder, r = await client_factory(responder_handshake=True)
        r['iccsn'] = 2 ** 23
        r['icck'] = cookie_factory()

        class _MockProtocol(ServerProtocol):
            async def keep_alive_loop(self):
                await sending_in_progress_future
                raise exception.PingTimeoutError('Meh!')

            async def initiator_receive_loop(self):
                try:
                    return await super().initiator_receive_loop()
                except asyncio.CancelledError:
                    cancelled_future.set_result(None)
                    raise

        mocker.patch.object(server, '_protocol_class', _MockProtocol)

        # Initiator handshake
        initiator, i = await client_factory(initiator_handshake=True)
        i['rccsn'] = 98798981
        i['rcck'] = cookie_factory()

        # new-initiator
        await responder.recv()

        # Get initiator's PathClient instance
        path = server.paths.get(initiator_key.pk)
        path_client = path.get_responder(r['id'])
        _send = path_client._connection.send

        # Mock responder instance: Block forwarding on send
        async def _mock_send(*_):
            mocker.patch.object(path_client._connection, 'send', _send)
            await sleep(0.1)
            sending_in_progress_future.set_result(None)
            await sleep(5.0)
            cancelled_future.set_exception(asyncio.TimeoutError())

        mocker.patch.object(path_client._connection, 'send', _mock_send)

        # Schedule a blocking job to keep the send job behind
        async def blocking_job():
            await asyncio.shield(cancelled_future, loop=event_loop)
        await path_client.jobs.enqueue(blocking_job())

        # Send a relay message: initiator --> responder
        nonce = pack_nonce(i['rcck'], i['id'], r['id'], i['rccsn'])
        await initiator.send(nonce, b'\xfe' * 2**15, box=None)
        i['ccsn'] += 1

        # Wait for the sending procedure to be started, then wait for the keep-alive loop
        # to time out.
        await sending_in_progress_future

        # Expect the initiator's receive loop to be cancelled
        await cancelled_future

        # Responder: Receive 'disconnected' message
        message, *_ = await responder.recv()
        assert message == {'type': 'disconnected', 'id': i['id']}

        # Bye
        await responder.close()
        await server.wait_connections_closed()
