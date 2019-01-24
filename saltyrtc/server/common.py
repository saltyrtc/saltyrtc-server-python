"""
This package will be moved to `saltyrtc.common` as soon as a SaltyRTC
client is being written.
"""
import enum
from typing import (
    TYPE_CHECKING,
    Any,
    cast,
)

from .exception import MessageError
from .typing import (
    Nonce,
    PingInterval,
    SignedKeys,
)

if TYPE_CHECKING:
    from .protocol import PathClient

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
    'DropReason',
    'DEFAULT_DROP_REASON',
    'ClientState',
    'AddressType',
    'Address',
    'ServerAddress',
    'SERVER_ADDRESS',
    'ClientAddress',
    'InitiatorAddress',
    'INITIATOR_ADDRESS',
    'ResponderAddress',
    'MessageType',
    'validate_public_key',
    'validate_cookie',
    'validate_subprotocol',
    'validate_subprotocols',
    'validate_responder_id',
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
KEEP_ALIVE_INTERVAL_DEFAULT = PingInterval(3600)
KEEP_ALIVE_TIMEOUT = 30.0


class OverflowSentinel:
    """
    The combined sequence number will be set to this object if the
    counter did overflow.
    """


@enum.unique
class SubProtocol(enum.Enum):
    saltyrtc_v1 = 'v1.saltyrtc.org'


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


@enum.unique
class DropReason(enum.IntEnum):
    protocol_error = 3001
    internal_error = 3002
    drop_by_initiator = 3004
    initiator_could_not_decrypt = 3005


DEFAULT_DROP_REASON = DropReason.drop_by_initiator


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
    def next(self) -> 'ClientState':
        """
        Return the subsequent state.

        Raises :exc:`ValueError` in case there is no subsequent state.
        """
        return ClientState(self + 1)


@enum.unique
class AddressType(enum.Enum):
    server = 1
    initiator = 2
    responder = 3


class Address(int):
    """
    A valid SaltyRTC address must be in the range of 0x00 to 0xff.
    """
    def __new__(cls, value: int) -> 'Address':
        if not isinstance(value, int):
            raise ValueError('Invalid address: {}'.format(value))
        if not 0x00 <= value <= 0xff:
            raise ValueError('Invalid address: 0x{:02x}'.format(value))
        return cast('Address', super().__new__(cls, value))  # type: ignore

    @property
    def type(self) -> AddressType:
        if self == 0x00:
            return AddressType.server
        elif self == 0x01:
            return AddressType.initiator
        else:
            return AddressType.responder


class ServerAddress(Address):
    """
    SaltyRTC address towards the server (0x00).
    """
    def __new__(cls) -> 'ServerAddress':
        return cast('ServerAddress', super().__new__(cls, 0x00))


SERVER_ADDRESS = ServerAddress()


class ClientAddress(Address):
    """
    SaltyRTC address towards a client (0x01 to 0xff).
    """
    def __new__(cls, value: int) -> 'ClientAddress':
        address = cast('ClientAddress', super().__new__(cls, value))
        if address == SERVER_ADDRESS:
            raise ValueError('Invalid address: 0x{:02x}'.format(value))
        return address


class InitiatorAddress(ClientAddress):
    """
    SaltyRTC address towards the initiator (0x01).
    """
    def __new__(cls) -> 'InitiatorAddress':
        return cast('InitiatorAddress', super().__new__(cls, 0x01))


INITIATOR_ADDRESS = InitiatorAddress()


class ResponderAddress(ClientAddress):
    """
    SaltyRTC address towards a responder (0x02 to 0xff).
    """
    def __new__(cls, value: int) -> 'ResponderAddress':
        address = cast('ResponderAddress', super().__new__(cls, value))
        # Note: ServerAddress has already been ruled out at this point
        if address == INITIATOR_ADDRESS:
            raise ValueError('Invalid address: 0x{:02x}'.format(value))
        return address


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


def validate_public_key(key: Any) -> None:
    if not isinstance(key, bytes):
        raise MessageError('Invalid key: Must be `bytes` (is `{}`)'.format(type(key)))
    key_length = len(key)
    if key_length != KEY_LENGTH:
        raise MessageError('Invalid key: Invalid length ({} != {})'.format(
            key_length, KEY_LENGTH))


def validate_cookie(cookie: Any) -> None:
    if not isinstance(cookie, bytes):
        raise MessageError('Invalid cookie: Must be `bytes` (is `{}`)'.format(
            type(cookie)))
    if len(cookie) != COOKIE_LENGTH:
        raise MessageError('Invalid cookie: Invalid length ({} != {})'.format(
            len(cookie), COOKIE_LENGTH))


def validate_subprotocol(subprotocol: Any) -> None:
    if not isinstance(subprotocol, str):
        raise MessageError('Invalid sub-protocol: Must be `str` (is `{}`)'.format(
            type(subprotocol)))


def validate_subprotocols(subprotocols: Any) -> None:
    if not isinstance(subprotocols, (list, tuple)):
        raise MessageError('Sub-protocols not list or tuple (type `{}`)'.format(
            type(subprotocols)))
    for subprotocol in subprotocols:
        validate_subprotocol(subprotocol)


def validate_responder_id(id_: Any) -> ResponderAddress:
    try:
        return ResponderAddress(id_)
    except ValueError as exc:
        raise MessageError('Invalid responder id: {}'.format(id_)) from exc


def validate_ping_interval(ping_interval: Any) -> None:
    if not isinstance(ping_interval, int):
        raise MessageError('Invalid ping interval: Must be `int` (is `{}`)'.format(
            type(ping_interval)))
    if ping_interval < 0:
        raise MessageError('Invalid ping interval ({} >= 0)'.format(ping_interval))


def validate_drop_reason(reason: Any) -> DropReason:
    if reason is None:
        return DEFAULT_DROP_REASON
    try:
        return DropReason(reason)
    except ValueError as exc:
        raise MessageError('Invalid drop reason: {}'.format(reason)) from exc


def sign_keys(client: 'PathClient', nonce: Nonce) -> SignedKeys:
    # Sign server's public session key and client's public permanent key (in that
    # order)
    payload = b''.join((client.server_key.pk, client.client_key))
    try:
        _, signed_keys = client.sign_box.encrypt(payload, nonce=nonce, pack_nonce=False)
        return SignedKeys(cast(bytes, signed_keys))
    except ValueError as exc:
        raise MessageError('Could not sign keys') from exc
