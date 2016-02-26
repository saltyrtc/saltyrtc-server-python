import functools

from asyncio.tasks import _GatheringFuture, async
from asyncio import futures


def gather(*coros_or_futures, loop=None, return_exceptions=False,
           exceptions_cancel_tasks=False):
    """Return a future aggregating results from the given coroutines
    or futures.

    All futures must share the same event loop.  If all the tasks are
    done successfully, the returned future's result is the list of
    results (in the order of the original sequence, not necessarily
    the order of results arrival).  If *return_exceptions* is True,
    exceptions in the tasks are treated the same as successful
    results, and gathered in the result list; otherwise, the first
    raised exception will be immediately propagated to the returned
    future.  If *exceptions_cancel_tasks* is True, the first raised
    exception in one child will cancel any other children.  Note that
    *return_exceptions* and *exceptions_cancel_tasks* are mutually
    exclusive.

    Cancellation: if the outer Future is cancelled, all children (that
    have not completed yet) are also cancelled.  If any child is
    cancelled, this is treated as if it raised CancelledError --
    the outer Future is *not* cancelled in this case.  (This is to
    prevent the cancellation of one child to cause other children to
    be cancelled.)
    """
    if return_exceptions and exceptions_cancel_tasks:
        raise ValueError("return_exceptions and exceptions_cancel_tasks are"
                         "mutually exclusive")

    if not coros_or_futures:
        outer = futures.Future(loop=loop)
        outer.set_result([])
        return outer

    arg_to_fut = {}
    for arg in set(coros_or_futures):
        if not isinstance(arg, futures.Future):
            fut = async(arg, loop=loop)
            if loop is None:
                loop = fut._loop
            # The caller cannot control this future, the "destroy pending task"
            # warning should not be emitted.
            fut._log_destroy_pending = False
        else:
            fut = arg
            if loop is None:
                loop = fut._loop
            elif fut._loop is not loop:
                raise ValueError("futures are tied to different event loops")
        arg_to_fut[arg] = fut

    children = [arg_to_fut[arg] for arg in coros_or_futures]
    nchildren = len(children)
    outer = _GatheringFuture(children, loop=loop)
    nfinished = 0
    results = [None] * nchildren

    def _done_callback(i, fut):
        nonlocal nfinished
        if outer.done():
            if not fut.cancelled():
                # Mark exception retrieved.
                fut.exception()
            return

        if fut.cancelled():
            res = futures.CancelledError()
            if not return_exceptions:
                outer.set_exception(res)
                return
        elif fut._exception is not None:
            res = fut.exception()  # Mark exception retrieved.
            if not return_exceptions:
                if exceptions_cancel_tasks:
                    for _fut in children:
                        _fut.cancel()
                outer.set_exception(res)
                return
        else:
            res = fut._result
        results[i] = res
        nfinished += 1
        if nfinished == nchildren:
            outer.set_result(results)

    for i, fut in enumerate(children):
        fut.add_done_callback(functools.partial(_done_callback, i))
    return outer
