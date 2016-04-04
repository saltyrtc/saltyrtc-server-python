"""
This module provides utility functions for the SaltyRTC Signalling
Server.
"""
from contextlib import contextmanager

from saltyrtc.server import config
from streql import equals as _equals

__all__ = (
    'Logger',
    'get_logger',
    'get_logging_handler',
    'consteq',
)


try:
    # noinspection PyPackageRequirements,PyUnresolvedReferences
    import logbook
except ImportError:
    class Logger(object):
        """
        Dummy logger in case :mod:`logbook` is not present.
        """
        def __init__(self, name, level=0):
            self.name = name
            self.level = level
        debug = info = warn = warning = notice = error = exception = \
            critical = log = lambda *a, **kw: None
else:
    class Logger(logbook.Logger):
        """
        Disable logger depending on config.
        """
        @property
        def disabled(self):
            return config.logging is False

    # Enable debug logging for `asyncio`
    import os
    # Enable asyncio debug logging
    os.environ['PYTHONASYNCIODEBUG'] = '1'

    import logbook.compat
    import logging

    # Redirect asyncio logger
    _logger = logging.getLogger('asyncio')
    _logger.setLevel(logging.INFO)
    _logger.addHandler(logbook.compat.RedirectLoggingHandler())


def _get_log_level():
    """
    Return the translated log level in case :mod:`logbook` is present.
    """
    try:
        # noinspection PyUnresolvedReferences,PyPackageRequirements
        from logbook import lookup_level
    except ImportError:
        return config.log_level
    else:
        return lookup_level(config.log_level)


def _get_logging_handler():
    """
    Return a :class:`~logbook.more.ColorizedStderrHandler` instance
    in case :mod:`logbook` is present. Otherwise return a mock handler.
    """
    try:
        # noinspection PyPackageRequirements,PyUnresolvedReferences
        import logbook.more
    except ImportError:
        class _LoggingHandler:
            @contextmanager
            def applicationbound(self):
                yield

        return _LoggingHandler()
    else:
        return logbook.more.ColorizedStderrHandler()


def get_logger(name=None):
    """
    Return the default :class:`Logger` instance of the library.

    Arguments:
        - `name`: The name of a specific sub-logger.
    """
    base_name = 'saltyrtc'
    name = base_name if name is None else '.'.join((base_name, name))
    return Logger(name, level=_get_log_level())


def get_logging_handler():
    """
    Return the logging handler.
    """
    return _get_logging_handler()


def consteq(left, right):
    """
    Check two strings/bytes for equality. This is functionally
    equivalent to ``left == right``, but attempts to take constant time
    relative to the size of the right hand input.

    See :func:`streql.equals` for details.
    """
    return _equals(left, right)
