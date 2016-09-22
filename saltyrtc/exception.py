"""
Contains all exceptions used for the SaltyRTC server.
"""
__all__ = (
    'SignalingError',
    'PathError',
    'SlotsFullError',
    'MessageFlowError',
    'PingTimeoutError',
    'Disconnected',
    'MessageError',
)


class SignalingError(Exception):
    """
    General error of this module. All other exceptions are derived from
    this class.
    """


class PathError(SignalingError):
    """
    TODO: Describe
    """


class SlotsFullError(SignalingError):
    """
    No free slot for a responder.
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


class MessageError(SignalingError):
    """
    Raised when a message is invalid.
    """
