"""
This package will be moved to `saltyrtc.common` as soon as a SaltyRTC
client is being written.
"""
import enum

from .exception import MessageError

__all__ = (
    'DATA_LENGTH_MIN',
    'KEY_LENGTH',
    'NONCE_LENGTH',
    'NONCE_FORMATTER',
    'COOKIE_LENGTH',
    'HASH_LENGTH',
    'SIGNED_KEYS_CIPHERTEXT_LENGTH',
    'RELAY_TIMEOUT',
    'KEEP_ALIVE_INTERVAL_MIN',
    'KEEP_ALIVE_INTERVAL_DEFAULT',
    'KEEP_ALIVE_TIMEOUT',
    'OverflowSentinel',
    'SubProtocol',
    'CloseCode',
    'ClientState',
    'AddressType',
    'MessageType',
    'available_slot_range',
    'is_client_id',
    'is_initiator_id',
    'is_responder_id',
    'validate_public_key',
    'validate_subprotocols',
    'validate_cookie',
    'validate_signed_keys',
    'validate_initiator_connected',
    'validate_client_id',
    'validate_responder_id',
    'validate_responder_ids',
    'validate_hash',
    'validate_ping_interval',
    'validate_drop_reason',
    'sign_keys',
)

DATA_LENGTH_MIN = 25
KEY_LENGTH = 32
NONCE_LENGTH = 24
NONCE_FORMATTER = '!16s2B6s'
COOKIE_LENGTH = 16
HASH_LENGTH = 32
SIGNED_KEYS_CIPHERTEXT_LENGTH = 80
RELAY_TIMEOUT = 30.0
KEEP_ALIVE_INTERVAL_MIN = 1.0
KEEP_ALIVE_INTERVAL_DEFAULT = 3600.0
KEEP_ALIVE_TIMEOUT = 30.0


class OverflowSentinel:
    """
    The combined sequence number will be set to this object if the
    counter did overflow.
    """


@enum.unique
class SubProtocol(enum.Enum):
    saltyrtc_v1 = 'v1.saltyrtc.org'


# Valid drop responder reasons
_drop_reasons = {3001, 3002, 3004, 3005}


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
    invalid_key = 3007
    timeout = 3008

    @property
    def is_valid_drop_reason(self):
        return self.value in _drop_reasons


@enum.unique
class ClientState(enum.IntEnum):
    """
    The state of a :class:`PathClient`.

    .. important:: States MUST follow the exact order as enumerated
                   below. A client cannot go back a state or skip
                   a state in between. For example, a *dropped* client
                   MUST have been formerly *authenticated*.
    """
    # The client is connected but is not allowed to communicate
    # with another client.
    restricted = 1

    # The client has been authenticated and may communicate with
    # other clients (of different type).
    authenticated = 2

    # The client has been dropped by another client.
    dropped = 3

    @property
    def next(self):
        """
        Return the subsequent state.

        Raises :exc:`ValueError` in case there is no subsequent state.
        """
        return ClientState(self + 1)


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
    disconnected = 'disconnected'


def available_slot_range():
    return range(0x01, 0xff + 1)


def is_client_id(id_):
    return 0x01 <= id_ <= 0xff


def is_initiator_id(id_):
    return id_ == 0x01


def is_responder_id(id_):
    return 0x01 < id_ <= 0xff


def validate_public_key(key):
    if not isinstance(key, bytes):
        raise MessageError('Invalid key: Must be `bytes` (is `{}`)'.format(type(key)))
    key_length = len(key)
    if key_length != KEY_LENGTH:
        raise MessageError('Invalid key: Invalid length ({} != {})'.format(
            key_length, KEY_LENGTH))


def validate_cookie(cookie):
    if not isinstance(cookie, bytes):
        raise MessageError('Invalid cookie: Must be `bytes` (is `{}`)'.format(
            type(cookie)))
    if len(cookie) != COOKIE_LENGTH:
        raise MessageError('Invalid cookie: Invalid length ({} != {})'.format(
            len(cookie), COOKIE_LENGTH))


def validate_subprotocols(subprotocols):
    try:
        iter(subprotocols)
    except TypeError as exc:
        raise MessageError('Sub-protocol list is not iterable (type `{}`)'.format(
            type(subprotocols))) from exc


def validate_signed_keys(signed_keys):
    expected_length = SIGNED_KEYS_CIPHERTEXT_LENGTH
    if not isinstance(signed_keys, bytes):
        error = "Invalid value for field 'signed_keys', must be `bytes` (is `{}`)".format(
            type(signed_keys))
        raise MessageError(error)
    signed_keys_length = len(signed_keys)
    if signed_keys_length != expected_length:
        raise MessageError("Invalid length of field 'signed_keys' ({} != {})".format(
            signed_keys_length, expected_length))


def validate_initiator_connected(initiator_connected):
    if not isinstance(initiator_connected, bool):
        error = "Invalid value for field 'initiator_connected', must be `bool` " \
                "(is `{}`)".format(type(initiator_connected))
        raise MessageError(error)


def validate_client_id(id_):
    if not is_client_id(id_):
        raise MessageError('Invalid client id: {}'.format(id_))


def validate_responder_id(id_):
    if not is_responder_id(id_):
        raise MessageError('Invalid responder id: {}'.format(id_))


def validate_responder_ids(ids):
    try:
        iterator = iter(ids)
    except TypeError as exc:
        raise MessageError('Responder list is not iterable') from exc
    for responder in iterator:
        validate_responder_id(responder)


def validate_hash(hash_):
    if not isinstance(hash_, bytes):
        raise MessageError('Invalid hash: Must be `bytes` (is `{}`)'.format(type(hash_)))
    hash_length = len(hash_)
    if hash_length != HASH_LENGTH:
        raise MessageError('Invalid hash: Invalid length ({} != {})'.format(
            hash_length, HASH_LENGTH))


def validate_ping_interval(ping_interval):
    if not isinstance(ping_interval, int):
        raise MessageError('Invalid ping interval: Must be `int` (is `{}`)'.format(
            type(ping_interval)))
    if ping_interval < 0:
        raise MessageError('Invalid ping interval ({} >= 0)'.format(ping_interval))


def validate_drop_reason(reason):
    # Default drop reason
    if reason is None:
        return CloseCode.drop_by_initiator

    # Validate reason
    try:
        reason = CloseCode(reason)
    except ValueError:
        raise MessageError('Invalid close code: {}'.format(reason))
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
