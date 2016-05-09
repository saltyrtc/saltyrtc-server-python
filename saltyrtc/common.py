import enum

from .exception import *

__all__ = (
    'KEY_LENGTH',
    'COOKIE_LENGTH',
    'HASH_LENGTH',
    'RELAY_TIMEOUT',
    'KEEP_ALIVE_TIMEOUT',
    'KEEP_ALIVE_INTERVAL',
    'SubProtocol',
    'CloseCode',
    'ReceiverType',
    'MessageType',
    'validate_public_key',
    'validate_cookie',
    'validate_responder_id',
    'validate_responder_ids',
    'validate_hash',
)


KEY_LENGTH = 32
COOKIE_LENGTH = 16
HASH_LENGTH = 32
RELAY_TIMEOUT = 30.0  # TODO: Sane?
KEEP_ALIVE_TIMEOUT = 30.0  # TODO: Sane?
KEEP_ALIVE_INTERVAL = 60.0  # TODO: Sane?


@enum.unique
class SubProtocol(enum.Enum):
    saltyrtc_v1_0 = 'saltyrtc-1.0'


@enum.unique
class CloseCode(enum.IntEnum):
    sub_protocol_error = 1002
    path_full_error = 3000
    protocol_error = 3001
    internal_error = 3002
    data_channel_handover = 3003


@enum.unique
class ReceiverType(enum.IntEnum):
    server = 0x00
    initiator = 0x01
    responder = 0xff

    @classmethod
    def from_receiver(cls, receiver):
        if receiver > 0x01:
            return cls.responder
        else:
            return cls(receiver)


@enum.unique
class MessageType(enum.Enum):
    """left out client-to-client message types"""
    server_hello = 'server-hello'
    client_hello = 'client-hello'
    client_auth = 'client-auth'
    server_auth = 'server-auth'
    new_responder = 'new-responder'
    drop_responder = 'drop-responder'
    send_error = 'send-error'


def validate_public_key(key):
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise MessageError('Invalid key')


def validate_cookie(cookie):
    if not isinstance(cookie, bytes) or len(cookie) != COOKIE_LENGTH:
        raise MessageError('Invalid cookie')


def validate_responder_id(responder):
    if not isinstance(responder, int) or not 0x01 < responder <= 0xff:
        raise MessageError('Invalid responder in responder list')


def validate_responder_ids(responders):
    try:
        iterator = iter(responders)
    except TypeError as exc:
        raise MessageError('Responder list is not iterable') from exc
    for responder in iterator:
        validate_responder_id(responder)


def validate_hash(hash_):
    if not isinstance(hash_, bytes) or len(hash_) != HASH_LENGTH:
        raise MessageError('Invalid hash')
