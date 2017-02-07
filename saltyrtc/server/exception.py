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
    'Disconnected',
    'MessageError',
    'DowngradeError',
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
    TODO: Describe
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
    TODO: Describe
    """


class PingTimeoutError(SignalingError):
    """
    TODO: Describe
    """
    def __init__(self, client):
        self.client = client

    def __str__(self):
        return 'Ping to {} timed out'.format(*self.args)


class Disconnected(Exception):
    """
    TODO: Describe
    """
    def __init__(self, reason: int = None):
        self.reason = reason


class MessageError(SignalingError):
    """
    Raised when a message is invalid.
    """


class DowngradeError(SignalingError):
    """
    A protocol downgrade has been detected.
    """
