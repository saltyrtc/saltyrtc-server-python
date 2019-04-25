"""
Contains all exceptions used for the SaltyRTC server.
"""
__all__ = (
    'SignalingError',
    'InternalError',
    'PathError',
    'SlotsFullError',
    'ServerKeyError',
    'MessageFlowError',
    'PingTimeoutError',
    'MessageError',
    'DowngradeError',
    'Disconnected',
)


class SignalingError(Exception):
    """
    General error of this module. All other exceptions are derived from
    this class.
    """


class InternalError(SignalingError):
    """
    Server misbehaved. Always report occurrences of this error!
    """


class PathError(SignalingError):
    """
    Invalid path provided by the client.
    """


class SlotsFullError(SignalingError):
    """
    No free slot for a responder.
    """


class ServerKeyError(SignalingError):
    """
    Raised when the server either does not have a permanent key pair
    but the client requested one or the server does not have the key
    pair that has been requested.
    """


class MessageFlowError(SignalingError):
    """
    Raised when an associated message is considered valid but it has
    been sent or received at a point in time where it's unexpected or
    other circumstances prevent it from being processed (such as a
    combined sequence number overflow).
    """


class PingTimeoutError(SignalingError):
    """
    The client did not respond to a WebSocket *ping* in time.

    Arguments:
        - `client_name`: The *name* of the client that did not respond.
    """
    def __init__(self, client_name: str) -> None:
        self.client_name = client_name

    def __str__(self) -> str:
        return 'Ping to {} timed out'.format(self.client_name)


class MessageError(SignalingError):
    """
    Raised when a message is invalid.
    """


class DowngradeError(SignalingError):
    """
    A protocol downgrade has been detected.
    """


class Disconnected(Exception):
    """
    The client disconnected from the server or has been disconnected by
    the server (e.g. by a drop request).

    ..note:: This does not derive from :class:`SignalingError` since it
             is not considered an *error*.
    """
    def __init__(self, reason: int) -> None:
        self.reason = reason
