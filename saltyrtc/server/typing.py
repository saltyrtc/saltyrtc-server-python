from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    List,
    MutableMapping,
    NewType,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

import libnacl.public

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    import logbook  # noqa
    # noinspection PyUnresolvedReferences
    from .events import Event  # noqa

__all__ = (
    'NoReturn',
    'ListOrTuple',
    'PathHex',
    'ServerPublicPermanentKey',
    'InitiatorPublicPermanentKey',
    'ResponderPublicSessionKey',
    'ClientPublicKey',
    'SequenceNumber',
    'OutgoingSequenceNumber',
    'IncomingSequenceNumber',
    'ServerCookie',
    'ClientCookie',
    'ChosenSubProtocol',
    'PingInterval',
    'SignedKeys',
    'MessageId',
    'DisconnectedData',
    'EventData',
    'EventCallback',
    'Nonce',
    'Packet',
    'EncryptedPayload',
    'RawPayload',
    'Payload',
    'ServerSecretPermanentKey',
    'ServerSecretSessionKey',
    'MessageBox',
    'SignBox',
    'Job',
    'Result',
    'Logger',
    'LogbookLevel',
    'LoggingLevel',
)

# Unconstrained type variables
# Important: Do not export!
T = TypeVar('T')  # Any type

# NoReturn
try:
    from typing import NoReturn
except ImportError:
    NoReturn = None


# Helpers
# -------

# List or Tuple
ListOrTuple = Union[List[T], Tuple[T]]


# Common
# ------

# The path in hexadecimal representation
PathHex = NewType('PathHex', str)

# One of the server's public keys (chosen by the client)
ServerPublicPermanentKey = NewType('ServerPublicPermanentKey', bytes)
# The initiator's public permanent key
InitiatorPublicPermanentKey = NewType('InitiatorPublicPermanentKey', bytes)
# The responder's public session key
ResponderPublicSessionKey = NewType('ResponderPublicSessionKey', bytes)
# The client's public key is either
#   a) the initiator's public permanent key (during the handshake), or
#   b) the client's public session key (updated after the handshake).
ClientPublicKey = Union[InitiatorPublicPermanentKey, ResponderPublicSessionKey]

# An incoming or outgoing sequence number
SequenceNumber = NewType('SequenceNumber', int)
# The server's outgoing sequence number
OutgoingSequenceNumber = NewType('OutgoingSequenceNumber', SequenceNumber)
# The client's incoming sequence number
IncomingSequenceNumber = NewType('IncomingSequenceNumber', SequenceNumber)

# The server's chosen cookie
ServerCookie = NewType('ServerCookie', bytes)
# The client's chosen cookie
ClientCookie = NewType('ClientCookie', bytes)

# One of the sub-protocols the client offered during the websocket
# sub-protocol negotiation
ChosenSubProtocol = NewType('ChosenSubProtocol', str)
# The negotiated ping interval
PingInterval = NewType('PingInterval', int)
# Signed keys to be provided to the user
SignedKeys = NewType('SignedKeys', bytes)
# The message id of a message that is in the progress of being relayed
MessageId = NewType('MessageId', bytes)


# Events
# ------

# Data provided to the registered callbacks
DisconnectedData = NewType('DisconnectedData', int)
EventData = Union[
    None,  # `initiator-connected` / `responder-connected`
    DisconnectedData,
]
# The event callback as provided by the user
EventCallback = Callable[['Event', Optional[PathHex], EventData], Awaitable[None]]


# Message
# -------

# Nonce
Nonce = NewType('Nonce', bytes)
# A packet including nonce and payload as bytes as received/sent
Packet = NewType('Packet', bytes)
# An encrypted payload (can be decrypted to a raw payload)
EncryptedPayload = NewType('EncryptedPayload', bytes)
# A raw payload (can be unpacked to a payload)
RawPayload = NewType('RawPayload', bytes)
# The payload as expected by the protocol (always dict-like in our implementation)
Payload = MutableMapping[str, Any]


# Protocol
# --------

# One of the server's secret permanent key pairs
ServerSecretPermanentKey = NewType('ServerSecretPermanentKey', libnacl.public.SecretKey)
# The server's secret session key pair
ServerSecretSessionKey = NewType('ServerSecretSessionKey', libnacl.public.SecretKey)
# Box for encrypting/decrypting messages
MessageBox = NewType('MessageBox', libnacl.public.Box)
# Box for "signing" the keys in the 'server-auth' message
SignBox = NewType('SignBox', libnacl.public.Box)
# A job of the job queue
Job = Awaitable[None]


# Task
# ----

# A consolidated result
Result = NewType('Result', BaseException)


# Util
# ----

# :mod:`logbook` Logger abstraction
Logger = Any
# A :mod:`logbook` log level
LogbookLevel = NewType('LogbookLevel', int)
# A :mod:`logging` log level
LoggingLevel = NewType('LoggingLevel', int)
