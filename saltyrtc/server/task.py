import asyncio
import enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Optional,
    Set,
    Union,
    cast,
)

from . import util
from .exception import (
    Disconnected,
    InternalError,
    PingTimeoutError,
    ServerKeyError,
    SignalingError,
    SlotsFullError,
)
from .typing import (
    Job,
    Logger,
    Result,
)

__all__ = (
    'FinalJob',
    'JobQueue',
    'Tasks',
)


def _log_exception(log: Logger, name: str, exc: BaseException) -> None:
    # Handle exception
    if isinstance(exc, Disconnected):
        log.debug('{} returned due to connection closed (code: {})',
                  name, exc.reason)
    elif isinstance(exc, PingTimeoutError):
        log.debug('{} returned due to ping timeout', name)
    elif isinstance(exc, SlotsFullError):
        log.debug('{} returned due to all path slots full: {}',
                  name, exc)
    elif isinstance(exc, ServerKeyError):
        log.debug('{} returned due to server key error: {}', name, exc)
    elif isinstance(exc, InternalError):
        log.error('{} returned due to an internal error: {}', name, exc)
    elif isinstance(exc, SignalingError):
        log.debug('{} returned due to protocol error: {}', name, exc)
    else:
        log.error('{} returned due to exception: {}', name, exc)


class FinalJob:
    """
    The job queue runner will stop if this has been dequeued from
    the job queue and the inner awaitable has returned a result.
    """
    def __init__(
            self,
            result_future: 'asyncio.Future[Result]',
            loop: asyncio.AbstractEventLoop,
    ):
        self.result_future = asyncio.shield(result_future, loop=loop)


@enum.unique
class JobQueueState(enum.IntEnum):
    open = 1
    closed = 2
    cancelled = 3
    completed = 4


class JobQueue:
    """
    An ordered queue of jobs (coroutines) which can be enqueued.

    A job queue runner can be started once ready which will process
    jobs, one by one.

    Once closed, the runner will continue to process pending jobs but
    no further jobs can be enqueued.

    When cancelled, all pending jobs will be cancelled and the runner
    will be stopped.

    Joining the job queue will block until all pending jobs have been
    processed.
    """
    __slots__ = (
        '_log',
        '_loop',
        '_state',
        '_queue',
        '_runner',
        '_active_job',
        '_final_job',
    )

    def __init__(
            self,
            log: Logger,
            loop: asyncio.AbstractEventLoop,
            final_job: FinalJob,
    ) -> None:
        self._log = log
        self._loop = loop
        self._state = JobQueueState.open  # type: JobQueueState
        self._queue = \
            asyncio.Queue(loop=self._loop)  # type: asyncio.Queue[Union[Job, FinalJob]]

        # Job runner
        self._runner = None  # type: Optional[asyncio.Task[None]]
        self._active_job = None  # type: Optional[Job]
        self._final_job = final_job

    async def enqueue(self, job: Job) -> None:
        """
        Enqueue a job into the job queue of the client.

        .. important:: Only the following jobs shall be enqueued:
                       - Messages from the server towards this client.
                       - Messages from other clients **towards** this
                         client (i.e. relayed messages).
                       - Delayed close operations towards this client.

        .. note:: Coroutines will be closed and :class:`asyncio.Task`s
                  will be cancelled when the job queue has been closed
                  or cancelled. The awaitable must be prepared for that.

        Arguments:
            - `job`: A coroutine or a :class:`asyncio.Task`.
        """
        if self._state == JobQueueState.open:
            await self._queue.put(job)
        else:
            util.cancel_awaitable(job, self._log)

    def close(self, *jobs: Job) -> None:
        """
        Close the job queue to prevent further enqueues. Will do
        nothing in case the job queue has already been closed or
        cancelled.

        Arguments:
            - `jobs`: A sequence of jobs that will be enqueued before
              the job queue is being closed.

        .. note:: Coroutines will be closed and :class:`asyncio.Task`s
                  will be cancelled when the job queue has been closed
                  or cancelled. The awaitable must be prepared for that.

        .. note:: Unlike :func:`~JobQueue.cancel`, this does
                  not cancel any pending jobs.
        """
        # Ignore if already closed or cancelled
        if self._state >= JobQueueState.closed:
            for job in jobs:
                util.cancel_awaitable(job, self._log)
            return

        # Update state
        self._state = JobQueueState.closed
        self._log.debug('Closed job queue')

        # Ask the job queue runner to stop when done processing all previous jobs.
        self._stop(*jobs)

    def cancel(self) -> None:
        """
        Cancel all pending jobs of the job queue and prevent further
        enqueues. Will do nothing in case the job queue has already
        been cancelled.
        """
        # Ignore if already cancelled
        if self._state >= JobQueueState.cancelled:
            return

        # Cancel active and all pending jobs
        self._cancel()

        # Ask the job queue runner to stop asap.
        # Note: If the final job had been enqueued formerly, it would have been
        #       dequeued in the block above, so we need to re-enqueue it.
        self._stop()

    async def join(self) -> None:
        """
        Block until all jobs of the job queue have been processed.

        Raises :exc:`InternalError` in case the job queue runner is not
        active.
        """
        self._log.debug(
            'Joining job queue (state={}, #jobs={})',
            self._state.name, self._queue.qsize())

        # Ensure the job queue runner started
        if self._runner is None:
            raise InternalError('Tried joining but job queue runner not started')

        # Join and wait for the job queue runner to exit
        try:
            await asyncio.gather(self._queue.join(), self._runner, loop=self._loop)
        except asyncio.CancelledError:
            # Cancel active job and all pending jobs
            self._cancel()

    def start(self, result_handler: Callable[[Result], None]) -> None:
        """
        Start the task queue runner.

        Will call `result_handler` each time a processed job raises
        an exception.

        Raises :exc:`InternalError` in case the job queue runner is
        already running.
        """
        if self._runner is not None:
            raise InternalError('Tried starting but job queue runner already active')

        # Start
        self._log.debug('Job queue runner started')
        self._runner = self._loop.create_task(self._run(result_handler))

    def _cancel(self) -> None:
        """
        Cancel active and all pending jobs. Return whether the final
        job has been removed.

        Add a 'done' callback to each job in order to mark the job
        queue as 'closed' after all functions, which may want to handle
        the cancellation, have handled that cancellation.

        This for example prevents a 'disconnect' message from being
        sent before a 'send-error' message has been sent, see:
        https://github.com/saltyrtc/saltyrtc-server-python/issues/77
        """
        if self._state < JobQueueState.cancelled:
            self._state = JobQueueState.cancelled
        if self._active_job is not None:
            self._log.debug('Cancelling active job')
            # Note: We explicitly DO NOT add the 'job done' callback here since the job
            #       does that in all cases.
            util.cancel_awaitable(self._active_job, self._log)
            self._active_job = None
        self._log.debug('Cancelling {} queued jobs', self._queue.qsize())
        while True:
            try:
                job = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if job is self._final_job:
                self._job_done(job, silent=True)
            else:
                awaitable = cast(Awaitable[None], job)
                util.cancel_awaitable(awaitable, self._log, done_cb=self._job_done)

    def _job_done(self, job: Union[Job, FinalJob], silent: bool = False) -> None:
        """
        Mark a previously dequeued job as processed.

        Raises :exc:`InternalError` if called more times than there
        were jobs placed in the queue.
        """
        if not silent:
            self._log.debug('Job done {}', job)
        try:
            self._queue.task_done()
        except ValueError:
            raise InternalError('More jobs marked as done as were enqueued')

    def _stop(self, *jobs: Job) -> None:
        """
        Ask the job queue runner to stop eventually.
        """
        # Enqueue any last minute jobs and ask the job queue runner to stop
        # Warning: put_nowait can raise if we limit the queue size!
        for job in jobs:

            self._queue.put_nowait(job)
        self._queue.put_nowait(self._final_job)

    async def _run(self, result_handler: Callable[[Result], None]) -> None:
        """
        Process jobs until stopped.

        Will call `exception_handler`, cancel all pending jobs and exit
        in the next iteration when a job has raised an exception.
        """
        while True:
            # Get a job from the queue
            job = await self._queue.get()
            if job is self._final_job:
                self._state = JobQueueState.completed
                result = await self._final_job.result_future
                self._job_done(job)
                result_handler(result)
                break

            # Wait until complete and handle exceptions
            future = asyncio.ensure_future(cast(Awaitable[None], job), loop=self._loop)
            self._log.debug('Waiting for job to complete {}', future)
            self._active_job = future
            try:
                await future
            except BaseException as exc:
                self._active_job = None
                if isinstance(exc, asyncio.CancelledError):
                    self._log.debug('Active job cancelled {}', future)
                else:
                    self._log.debug('Stopping active job {}', future)
                    _log_exception(self._log, 'Job', exc)
                    self.cancel()
                    result_handler(Result(exc))
                # noinspection PyTypeChecker
                future.add_done_callback(self._job_done)
            else:
                self._active_job = None
                self._job_done(future)

        # Bye
        self._log.debug('Job queue runner done')


class Tasks:
    """
    Contains one or more tasks that can be started at once.

    Tasks are expected to return with an exception. They may also be
    cancelled as long as a result (in form of an exception) has been
    determined.
    """
    __slots__ = (
        '_log',
        '_loop',
        '_cancelled',
        '_result_set',
        '_result_future',
        '_tasks',
        '_tasks_remaining',
    )

    def __init__(
            self,
            log: Logger,
            loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._log = log
        self._loop = loop
        self._cancelled = False
        self._result_set = False
        self._result_future = \
            asyncio.Future(loop=self._loop)  # type: asyncio.Future[Result]
        self._tasks = None  # type: Optional[Set[asyncio.Task[None]]]
        self._tasks_remaining = 0

    def start(self, coroutines: Set[Coroutine[Any, Any, None]]) -> None:
        """
        Start coroutines by transforming them to tasks.

        Arguments:
            - `coroutines`: A set of coroutines that **may never return**.

        Raises :exc:`InternalError` if already started.

        .. note:: All tasks will be immediately cancelled if requested
                  by another client prior to this method being called.
        """
        if self._tasks is not None:
            raise InternalError('Tasks already started')

        # Bind done callbacks
        tasks = {self._loop.create_task(coroutine) for coroutine in coroutines}
        for task in tasks:
            self._tasks_remaining += 1
            task.add_done_callback(self._task_done_handler)

        # Store tasks
        self._tasks = tasks

        # Cancel tasks?
        if self._cancelled:
            self._cancel()

    def cancel(self, result: Union[Result, 'asyncio.Future[Result]']) -> None:
        """
        Cancel all tasks and all tasks that will be started in the
        future.
        """
        if self._cancelled:
            return

        # Set result (immediate or delayed)
        self._set_result(result)

        # Cancel all tasks
        self._cancel()
        self._cancelled = True

    def await_result(self) -> 'asyncio.Future[Result]':
        """
        Wait for a result.

        Once the :class:`asyncio.Future` is done, all tasks are
        guaranteed to be done as well.
        """
        return asyncio.shield(self._result_future, loop=self._loop)

    def _task_done_handler(self, task: 'asyncio.Task[None]') -> None:
        assert self._tasks is not None
        self._tasks_remaining -= 1
        self._log.debug('Task done (#tasks={}, #running={}), {}',
                        len(self._tasks), self._tasks_remaining, task)

        # We don't care about cancelled tasks unless it's the last one and no exception
        # has been set.
        if task.cancelled():
            self._log.debug('Task was cancelled')
            if self._tasks_remaining == 0 and not self._result_set:
                error = 'All tasks have been cancelled prior to an exception'
                self._set_result(Result(InternalError(error)))
                self._cancelled = True
            return

        # Tasks may not ever return without an exception
        exc = task.exception()
        if exc is None:
            exc = InternalError('Task returned unexpectedly')
        result = Result(exc)

        # Store the result and cancel all running tasks
        _log_exception(self._log, 'Task', exc)
        self._set_result(result)
        self._cancel()

    def _set_result(self, result: Union[Result, 'asyncio.Future[Result]']) -> None:
        if not self._result_set:
            self._log.debug('Tasks result: {}, cancelling all remaining', type(result))
            self._result_set = True
            if isinstance(result, BaseException):
                self._result_future.set_result(result)
            else:
                result.add_done_callback(
                    lambda future: self._result_future.set_result(future.result()))

    def _cancel(self) -> None:
        if self._tasks is None:
            return
        for task in self._tasks:
            if not task.done():
                task.cancel()