"""
Contains all exceptions used for the SaltyRTC server.
"""
__all__ = (
    'SignalingError',
    'PathError',
    'RoleError',
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


class RoleError(SignalingError):
    """
    TODO: Describe
    """
    def __str__(self):
        return 'Unknown role {}'.format(*self.args)


class MessageFlowError(SignalingError):
    """
    TODO: Describe
    """


class PingTimeoutError(SignalingError):
    """
    TODO: Describe
    """
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
