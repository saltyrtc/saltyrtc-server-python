"""
This module provides utility functions for the SaltyRTC Signalling
Server.
"""
import binascii
import logging
import ssl

import libnacl
import libnacl.public

__all__ = (
    'logger_group',
    'enable_logging',
    'disable_logging',
    'get_logger',
    'consteq',
    'create_ssl_context',
    'load_permanent_key',
)


# noinspection PyUnusedLocal,PyPropertyDefinition
def _logging_error(*args, **kwargs):
    raise ImportError('Please install saltyrtc.server[logging] for logging support')


try:
    # noinspection PyPackageRequirements,PyUnresolvedReferences
    import logbook
except ImportError:
    class _Logger:
        """
        Dummy logger in case :mod:`logbook` is not present.
        """
        def __init__(self, name, level=0):
            self.name = name
            self.level = level
        debug = info = warn = warning = notice = error = exception = \
            critical = log = lambda *a, **kw: None

    class _LoggerGroup:
        """
        Dummy logger group in case :mod:`logbook` is not present.
        """
        def __init__(self, loggers=None, level=0, processor=None):
            self.loggers = loggers
            self.level = level
            self.processor = processor

        disabled = property(lambda: True, _logging_error)
        add_logger = remove_logger = process_record = _logging_error

    _logger_redirect_handler = None
    _logger_convert_level_handler = None
else:
    _Logger = logbook.Logger

    # noinspection PyPep8Naming
    def _LoggerGroup():
        group = logbook.LoggerGroup()
        group.disabled = True
        return group

    _logger_redirect_handler = logbook.compat.RedirectLoggingHandler()
    _logger_convert_level_handler = logbook.compat.LoggingHandler()


# Create logger group
logger_group = _LoggerGroup()


def _convert_level(logging_level):
    """
    Convert a :mod:`logging` level to a :mod:`logbook` level.

    Arguments:
        - `logging_level`: A :mod:`logging` level.

    Raises :class:`ImportError` in case :mod:`logbook` is not
    installed.
    """
    if _logger_convert_level_handler is None:
        _logging_error()
    return _logger_convert_level_handler.convert_level(logging_level)


def _redirect_logging_loggers(logging_loggers, remove=False):
    """
    Enable logging and redirect :mod:`logging` loggers of dependencies.

    Arguments:
        - `logging_loggers`: A dictionary containing :mod:`logging`
          logger names as key and their respective :mod:`logging` level
          as value. These loggers will be redirected to logbook.
        - `remove`: Flag to remove the redirect handler from each
          logger instead of adding it.

    Raises :class:`ImportError` in case :mod:`logbook` is not
    installed.
    """
    if _logger_redirect_handler is None:
        _logging_error()

    # At this point, logbook is either defined or an error has been returned
    for name, level in logging_loggers.items():
        # Lookup logger and translate level
        logger = logging.getLogger(name)
        logger.setLevel(_convert_level(level))

        # Add or remove redirect handler.
        if remove:
            logger.removeHandler(_logger_redirect_handler)
        else:
            logger.addHandler(_logger_redirect_handler)


def enable_logging(level=None, redirect_loggers=None):
    """
    Enable logging for the *saltyrtc* logger group.

    Arguments:
        - `level`: A :mod:`logbook` logging level. Defaults to
          ``WARNING``.
        - `redirect_loggers`: A dictionary containing :mod:`logging`
          logger names as key and their respective :mod:`logging` level
          as value. Each logger will be looked up and redirected to
          :mod:`logbook`. Defaults to an empty dictionary.

    Raises :class:`ImportError` in case :mod:`logbook` is not
    installed.
    """
    if _logger_convert_level_handler is None:
        _logging_error()

    # At this point, logbook is either defined or an error has been returned
    if level is None:
        level = logbook.WARNING
    logger_group.disabled = False
    logger_group.level = level
    if redirect_loggers is not None:
        _redirect_logging_loggers(redirect_loggers, remove=False)


def disable_logging(redirect_loggers=None):
    """
    Disable logging for the *saltyrtc* logger group.

    Arguments:
        - `level`: A :mod:`logbook` logging level.
        - `redirect_loggers`: A dictionary containing :mod:`logging`
          logger names as key and their respective :mod:`logging` level
          as value. Each logger will be looked up and removed from the
          redirect handler. Defaults to an empty dictionary.

    Raises :class:`ImportError` in case :mod:`logbook` is not
    installed.
    """
    logger_group.disabled = True
    if redirect_loggers is not None:
        _redirect_logging_loggers(redirect_loggers, remove=True)


def get_logger(name=None, level=None):
    """
    Return a :class:`logbook.Logger`.

    Arguments:
        - `name`: The name of a specific sub-logger.
        - `level`: A :mod:`logbook` logging level.
    """
    if _logger_convert_level_handler is None:
        _logging_error()

    # At this point, logbook is either defined or an error has been returned
    if level is None:
        level = logbook.NOTSET
    base_name = 'saltyrtc'
    name = base_name if name is None else '.'.join((base_name, name))

    # Create new logger and add to group
    logger = logbook.Logger(name=name, level=level)
    logger_group.add_logger(logger)
    return logger


def consteq(left, right):
    """
    Compares two byte instances with one another. If `a` and `b` have
    different lengths, return `False` immediately. Otherwise `a` and `b`
    will be compared in constant time.

    Return `True` in case `a` and `b` are equal. Otherwise `False`.

    Raises :exc:`TypeError` in case `a` and `b` are not both of the type
    :class:`bytes`.
    """
    return libnacl.bytes_eq(left, right)


def create_ssl_context(certfile, keyfile=None, dh_params_file=None):
    """
    Create and return a :class:`ssl.SSLContext` for the server.
    The settings are chosen by the :mod:`ssl` module, and usually
    represent a higher security level than when calling the
    :class:`ssl.SSLContext` constructor directly.

    Arguments:
        - `certfile`: Path to a file in PEM format containing the
          SSL certificate of the server.
        - `keyfile`: Path to a file that contains the private key.
          Will be read from `certfile` if not present.
        - `dh_params_file`: Path to a file in PEM format containing
          Diffie-Hellman parameters for DH(E) and ECDH(E). Optional
          but highly recommended.
    """
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if dh_params_file is not None:
        ssl_context.load_dh_params(dh_params_file)
    return ssl_context


def load_permanent_key(key):
    """
    Decode a hex-encoded NaCl private permanent key or read it from a
    file.

    Arguments:
        - `key`: A hex-encoded 32 bytes private permanent key or the
          name of a file which contains the key.

    Raises :exc:`ValueError` in case the key could not be found or
    is not a valid hex-encoded NaCl private key.

    Return a:class:`libnacl.public.SecretKey` instance.
    """
    # Read key file (if any)
    try:
        with open(key) as file:
            key = file.readline().strip()
    except IOError:
        pass

    # Un-hexlify
    try:
        key = binascii.unhexlify(key)
    except binascii.Error as exc:
        raise ValueError('Could not decode key') from exc

    # Convert to private key (raises ValueError on its own)
    return libnacl.public.SecretKey(sk=key)
