import enum

from .exception import *

__all__ = (
    'KEY_LENGTH',
    'NONCE_LENGTH',
    'NONCE_FORMATTER',
    'COOKIE_LENGTH',
    'HASH_LENGTH',
    'SIGNED_KEYS_CIPHERTEXT_LENGTH',
    'RELAY_TIMEOUT',
    'KEEP_ALIVE_TIMEOUT',
    'KEEP_ALIVE_INTERVAL',
    'SubProtocol',
    'CloseCode',
    'AddressType',
    'MessageType',
    'available_slot_range',
    'is_initiator_id',
    'is_responder_id',
    'validate_public_key',
    'validate_subprotocols',
    'validate_cookie',
    'validate_signed_keys',
    'validate_initiator_connected',
    'validate_responder_id',
    'validate_responder_ids',
    'validate_hash',
    'validate_drop_reason',
    'sign_keys',
)


KEY_LENGTH = 32
NONCE_LENGTH = 24
NONCE_FORMATTER = '!16s2B6s'
COOKIE_LENGTH = 16
HASH_LENGTH = 32
SIGNED_KEYS_CIPHERTEXT_LENGTH = 80
RELAY_TIMEOUT = 30.0  # TODO: Sane?
KEEP_ALIVE_TIMEOUT = 30.0  # TODO: Sane?
KEEP_ALIVE_INTERVAL = 60.0  # TODO: Sane?


@enum.unique
class SubProtocol(enum.Enum):
    saltyrtc_v1 = 'v0.saltyrtc.org'


@enum.unique
class CloseCode(enum.IntEnum):
    going_away = 1001
    subprotocol_error = 1002
    path_full_error = 3000
    protocol_error = 3001
    internal_error = 3002
    handover = 3003
    drop_by_initiator = 3004
    initiator_could_not_decrypt = 3005
    no_shared_tasks = 3006

    @property
    def is_valid_drop_reason(self):
        return self.value != 3003 and self.value in range(3001, 3006 + 1)


@enum.unique
class AddressType(enum.IntEnum):
    server = 0x00
    initiator = 0x01
    responder = 0xff

    @classmethod
    def from_address(cls, address):
        if address > 0x01:
            return cls.responder
        else:
            return cls(address)


@enum.unique
class MessageType(enum.Enum):
    """left out client-to-client message types"""
    server_hello = 'server-hello'
    client_hello = 'client-hello'
    client_auth = 'client-auth'
    server_auth = 'server-auth'
    new_responder = 'new-responder'
    new_initiator = 'new-initiator'
    drop_responder = 'drop-responder'
    send_error = 'send-error'


def available_slot_range():
    return range(0x01, 0xff + 1)


def is_initiator_id(id_):
    return id_ == 0x01


def is_responder_id(id_):
    return 0x01 < id_ <= 0xff


def validate_public_key(key):
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise MessageError('Invalid key')


def validate_cookie(cookie):
    if not isinstance(cookie, bytes):
        raise MessageError('Invalid cookie: Must be `bytes` instance')
    if len(cookie) != COOKIE_LENGTH:
        raise MessageError('Invalid cookie: Invalid length ({} != {})'.format(
            len(cookie), COOKIE_LENGTH))


def validate_subprotocols(subprotocols):
    try:
        iter(subprotocols)
    except TypeError as exc:
        raise MessageError('Sub-protocol list is not iterable') from exc


def validate_signed_keys(signed_keys):
    max_length = SIGNED_KEYS_CIPHERTEXT_LENGTH
    if not isinstance(signed_keys, bytes) or len(signed_keys) != max_length:
        raise MessageError("Invalid value for field 'signed_keys'")


def validate_initiator_connected(initiator_connected):
    if not isinstance(initiator_connected, bool):
        raise MessageError("Invalid value for field 'initiator_connected'")


def validate_responder_id(id_):
    if not is_responder_id(id_):
        raise MessageError('Invalid responder id in responder list')


def validate_responder_ids(ids):
    try:
        iterator = iter(ids)
    except TypeError as exc:
        raise MessageError('Responder list is not iterable') from exc
    for responder in iterator:
        validate_responder_id(responder)


def validate_hash(hash_):
    if not isinstance(hash_, bytes) or len(hash_) != HASH_LENGTH:
        raise MessageError('Invalid hash')


def validate_drop_reason(reason):
    # Default drop reason
    if reason is None:
        return CloseCode.drop_by_initiator

    # Validate reason
    try:
        reason = CloseCode(reason)
    except ValueError:
        raise MessageError('Invalid close code')
    if not reason.is_valid_drop_reason:
        raise MessageError('Reason not from acceptable range of close codes')

    return reason


def sign_keys(client, nonce):
    # Sign server's public session key and client's public permanent key (in that
    # order)
    payload = b''.join((client.server_key.pk, client.client_key))
    try:
        _, signed_keys = client.sign_box.encrypt(payload, nonce=nonce, pack_nonce=False)
        return signed_keys
    except ValueError as exc:
        raise MessageError('Could not sign keys') from exc
