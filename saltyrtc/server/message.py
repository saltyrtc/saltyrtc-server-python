import abc
import binascii
import io
import struct
from typing import ClassVar  # noqa
from typing import (
    TYPE_CHECKING,
    Any,
    MutableMapping,
    Optional,
    Tuple,
    Union,
    cast,
)

import libnacl
import umsgpack

from .common import (
    COOKIE_LENGTH,
    DATA_LENGTH_MIN,
    INITIATOR_ADDRESS,
    NONCE_FORMATTER,
    NONCE_LENGTH,
    SERVER_ADDRESS,
    Address,
    AddressType,
    ClientAddress,
    ClientState,
    DropReason,
    MessageType,
    OverflowSentinel,
    ResponderAddress,
    sign_keys as sign_keys_,
    validate_cookie,
    validate_drop_reason,
    validate_ping_interval,
    validate_public_key,
    validate_responder_id,
    validate_subprotocols,
)
from .exception import (
    MessageError,
    MessageFlowError,
)
from .typing import (
    ChosenSubProtocol,
    ClientCookie,
    ClientPublicKey,
    EncryptedPayload,
    IncomingSequenceNumber,
    ListOrTuple,
    MessageId,
    Nonce,
    Packet,
    Payload,
    PingInterval,
    RawPayload,
    ServerCookie,
    ServerPublicPermanentKey,
)

if TYPE_CHECKING:
    from .protocol import PathClient

__all__ = (
    'unpack',
    'BaseMessage',
    'BaseMessageMixin',
    'OutgoingMessageMixin',
    'IncomingMessageMixin',
    'RelayMessage',
    'CookedMessage',
    'OutgoingMessage',
    'IncomingMessage',
    'ServerHelloMessage',
    'ClientHelloMessage',
    'ClientAuthMessage',
    'ServerAuthMessage',
    'NewInitiatorMessage',
    'NewResponderMessage',
    'DropResponderMessage',
    'SendErrorMessage',
    'DisconnectedMessage',
)


def _message_representation(
        class_name: str,
        nonce: Optional[Nonce],
        payload: Union[RawPayload, Payload],
        encrypted: Optional[bool] = None,
) -> str:
    hex_cookie_length = COOKIE_LENGTH * 2
    if nonce is None:
        nonce_str = 'n/a'
    else:
        nonce_str = binascii.hexlify(nonce).decode('ascii')
        nonce_str = '|'.join((
            nonce_str[:hex_cookie_length],
            nonce_str[hex_cookie_length:hex_cookie_length + 2],
            nonce_str[hex_cookie_length + 2:hex_cookie_length + 4],
            nonce_str[hex_cookie_length + 4:hex_cookie_length + 8],
            nonce_str[hex_cookie_length + 8:]
        ))
    if encrypted is not None:
        encrypted_str = 'encrypted={}, '.format(encrypted)
    else:
        encrypted_str = ''
    return '{}({}nonce={}, data={})'.format(
        class_name, encrypted_str, nonce_str, payload)


def unpack(client: 'PathClient', data: Packet) -> 'IncomingMessageMixin':
    """
    MessageError
    MessageFlowError
    """
    return IncomingMessage.unpack(client, data)


class BaseMessage:
    type = None  # type: ClassVar[Union[MessageType, str]]

    def __init__(
            self,
            source: Address,
            destination: Address,
            nonce: Optional[Nonce] = None,
    ) -> None:
        self.source = source
        self.destination = destination
        self._nonce = nonce


class BaseMessageMixin(metaclass=abc.ABCMeta):
    type = None  # type: ClassVar[Union[str, MessageType]]


class OutgoingMessageMixin(BaseMessageMixin, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def pack(self, client: 'PathClient') -> Packet:
        """
        MessageError
        MessageFlowError
        """


class IncomingMessageMixin(BaseMessageMixin, metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def unpack(cls, client: 'PathClient', data: Packet) -> 'IncomingMessageMixin':
        """
         MessageError
         MessageFlowError
         """


class RelayMessage(BaseMessage, OutgoingMessageMixin, IncomingMessageMixin):
    # Note: This field is used for logging purposes only
    type = 'relay'  # type: ClassVar[str]

    def __init__(
            self,
            source: ClientAddress,
            destination: ClientAddress,
            data: Packet,
            nonce: Nonce,
    ) -> None:
        super().__init__(source, destination, nonce=nonce)
        self._data = data

    def __str__(self) -> str:
        payload = RawPayload(self._data[NONCE_LENGTH:])
        return _message_representation(
            self.__class__.__name__, self._nonce, payload)

    def pack(self, _: 'PathClient') -> Packet:
        return self._data

    @classmethod
    def unpack(cls, client: 'PathClient', data: Packet) -> 'RelayMessage':
        raise MessageError('Relay messages cannot be unpacked')


class CookedMessage(BaseMessage, metaclass=abc.ABCMeta):
    encrypted = None  # type: ClassVar[bool]

    def __new__(cls, *args: Any, **kwargs: Any) -> 'CookedMessage':
        # Ensure the class has implemented a class-level `type` attribute
        if cls.type not in MessageType:
            message = 'Cannot instantiate class {} with invalid message type: {}'
            raise TypeError(message.format(cls.__name__, cls.type))

        # Ensure the class has implemented a class-level `encrypted` flag
        if cls.encrypted is not True and cls.encrypted is not False:
            message = 'Cannot instantiate class {} with invalid encrypted flag: {}'
            raise TypeError(message.format(cls.__name__, cls.encrypted))

        return cast('CookedMessage', super().__new__(cls))

    def __init__(
            self,
            source: Address,
            destination: Address,
            payload: Payload,
            nonce: Optional[Nonce] = None,
            extra: Optional[MutableMapping[str, Any]] = None,
    ) -> None:
        super().__init__(source, destination, nonce=nonce)
        self.payload = {} if payload is None else payload  # type: Payload
        self.extra = {} if extra is None else extra  # type: MutableMapping[str, Any]

    def __str__(self) -> str:
        return _message_representation(
            self.__class__.__name__, self._nonce, self.payload, encrypted=self.encrypted)


class OutgoingMessage(CookedMessage, OutgoingMessageMixin, metaclass=abc.ABCMeta):
    def pack(self, client: 'PathClient') -> Packet:
        """
        MessageError
        MessageFlowError
        """
        data = io.BytesIO()

        # Pack nonce
        nonce = self._pack_nonce(client)
        self._nonce = nonce  # Stored for str representation
        data.write(nonce)

        # Prepare payload
        self.prepare_payload(client, nonce)

        # Pack payload
        raw_payload = self._pack_payload()

        # Encrypt payload if required
        payload = raw_payload  # type: Union[RawPayload, EncryptedPayload]
        if self.encrypted:
            if client.state != ClientState.authenticated:
                raise MessageFlowError('Cannot encrypt payload, not authenticated')
            payload = self._encrypt_payload(client, nonce, raw_payload)

        # Append payload and return as bytes
        data.write(payload)
        return Packet(data.getvalue())

    def prepare_payload(self, client: 'PathClient', nonce: Nonce) -> None:
        """
        This method will be called as soon as the nonce has been packed
        to make late changes to the payload based on the nonce. It is a
        no-op by default.

        Only :exc:`MessageError` may be raised.
        """
        return

    def _pack_nonce(self, client: 'PathClient') -> Nonce:
        """
        .. note:: The CSN check and incrementation can only reside here
                  because an error while packing a message will
                  create a protocol error in any case.

        MessageError
        MessageFlowError
        """
        # Ensure that the outgoing combined sequence number counter did not overflow
        if client.csn_out is OverflowSentinel:
            raise MessageFlowError(('Cannot send any more messages, due to a sequence '
                                    'number counter overflow'))

        # Pack nonce
        try:
            nonce = struct.pack(
                NONCE_FORMATTER,
                client.cookie_out,
                self.source, self.destination,
                struct.pack('!Q', client.csn_out)[2:]
            )
        except struct.error as exc:
            raise MessageError('Could not pack nonce') from exc

        # Increase outgoing combined sequence number counter
        client.increment_csn_out()
        return Nonce(nonce)

    def _pack_payload(self) -> RawPayload:
        try:
            return RawPayload(umsgpack.packb(self.payload))
        except umsgpack.PackException as exc:
            raise MessageError('Could not pack msgpack payload') from exc

    @classmethod
    def _encrypt_payload(
            cls,
            client: 'PathClient',
            nonce: Nonce,
            payload: RawPayload,
    ) -> EncryptedPayload:
        try:
            _, data = client.box.encrypt(payload, nonce=nonce, pack_nonce=False)
            return EncryptedPayload(cast(bytes, data))
        except (ValueError, libnacl.CryptError) as exc:
            raise MessageError('Could not encrypt payload') from exc


# noinspection PyAbstractClass
class IncomingMessage(CookedMessage, IncomingMessageMixin, metaclass=abc.ABCMeta):
    @classmethod
    def unpack(cls, client: 'PathClient', packet: Packet) -> IncomingMessageMixin:
        """
        MessageError
        MessageFlowError
        """
        # Check length
        length = len(packet)
        if length < DATA_LENGTH_MIN:
            raise MessageError('Message too short: {} bytes'.format(length))

        # Unpack and check nonce
        nonce, source, destination = cls._unpack_nonce(packet, client)

        # Decrypt if directed at us and keys have been exchanged
        # or just return a relay message to be sent to another client
        if destination.type == AddressType.server:
            expect_type = None
            data = packet[NONCE_LENGTH:]
            authenticated = \
                client.state == ClientState.authenticated and client.type is not None
            if not authenticated:
                payload = None

                # Try client-auth (encrypted)
                try:
                    payload = cls._unpack_payload(
                        cls._decrypt_payload(client, nonce, EncryptedPayload(data)))
                except MessageError:
                    pass
                else:
                    expect_type = MessageType.client_auth

                # Try client-hello (unencrypted)
                if payload is None:
                    try:
                        payload = cls._unpack_payload(RawPayload(data))
                    except MessageError:
                        pass
                    else:
                        expect_type = MessageType.client_hello

                # Still no payload?
                if expect_type is None or payload is None:
                    message = 'Expected either client-hello or client-auth, got neither'
                    raise MessageError(message)
            else:
                # Decrypt and unpack payload
                payload = cls._unpack_payload(
                    cls._decrypt_payload(client, nonce, EncryptedPayload(data)))

            # Unpack type
            try:
                type_ = payload.get('type')
            except AttributeError as exc:
                error = 'Message does not contain a dictionary: {}'
                raise MessageError(error.format(type(payload))) from exc
            try:
                type_ = MessageType(type_)
            except ValueError as exc:
                raise MessageError('Unknown message type: {}'.format(type_)) from exc

            # Ensure expected type isn't violated
            if expect_type is not None and type_ != expect_type:
                raise MessageError('Expected type {}, got {}'.format(expect_type, type_))

            # Create message from payload
            if not authenticated:
                # Note: `_unpack_nonce` ensures that both addresses are the server's
                #       address if the client is not authenticated.
                if type_ == MessageType.client_hello:
                    return ClientHelloMessage.from_payload(payload)
                if type_ == MessageType.client_auth:
                    return ClientAuthMessage.from_payload(payload)
            else:
                # Note: Validation of source address is required here since
                #       only an initiator may drop responders.
                if type_ == MessageType.drop_responder and source == INITIATOR_ADDRESS:
                    return DropResponderMessage.from_payload(payload)

            # Catch all
            raise MessageFlowError('Unexpected message type: {}'.format(type_))
        else:
            # Note: `_unpack_nonce` ensures that both addresses are client addresses if
            #       the destination is not the server.
            source, destination = ClientAddress(source), ClientAddress(destination)
            return RelayMessage(source, destination, packet, nonce)

    @classmethod
    def _unpack_nonce(
            cls,
            data: Packet,
            client: 'PathClient',
    ) -> Tuple[Nonce, Address, Address]:
        """
        It is critical that this function ensures...

        - that both `source` and `destination` are the server's address
          (0x00) in case the client is not authenticated, and
        - that both `source` and `destination` are of in the range of
          valid client addresses if `destination` is not the server's
          address.

        .. note:: The CSN check and incrementation can only reside here
                  because an error while unpacking a message will
                  create a protocol error in any case.

        MessageError
        MessageFlowError
        """
        nonce = data[:NONCE_LENGTH]
        try:
            cookie_in, source, destination, csn_in = struct.unpack(NONCE_FORMATTER, nonce)
            csn_in, *_ = struct.unpack(
                '!Q', b'\x00\x00' + csn_in)
        except struct.error as exc:
            raise MessageError('Could not unpack nonce') from exc
        csn_in = IncomingSequenceNumber(csn_in)

        # Validate source and destination address
        try:
            source, destination = Address(source), Address(destination)
        except ValueError as exc:
            raise MessageError('Invalid address in message') from exc

        # Validate destination
        # (Is the client allowed to send messages to the address type?)
        is_to_server = destination.type == AddressType.server
        if not is_to_server and not client.p2p_allowed(destination.type):
            error = 'Not allowed to relay messages to 0x{:02x}'
            raise MessageFlowError(error.format(destination))

        # Validate source
        if source != client.id:
            error_message = 'Identities do not match, expected 0x{:02x}, got 0x{:02x}'
            raise MessageError(error_message.format(client.id, source))

        # Validate cookie and increase combined sequence number
        if is_to_server:
            if not client.valid_cookie(cookie_in):
                raise MessageError('Invalid cookie: {}'.format(cookie_in))
            client.validate_csn_in(csn_in)
            client.increment_csn_in()

        return Nonce(nonce), source, destination

    @classmethod
    def _unpack_payload(cls, payload: RawPayload) -> Payload:
        try:
            return cast(Payload, umsgpack.unpackb(payload))
        except (umsgpack.UnpackException, TypeError) as exc:
            raise MessageError('Could not unpack msgpack payload') from exc

    @classmethod
    def _decrypt_payload(
            cls,
            client: 'PathClient',
            nonce: Nonce,
            data: EncryptedPayload,
    ) -> RawPayload:
        try:
            return RawPayload(client.box.decrypt(data, nonce=nonce))
        except (ValueError, libnacl.CryptError) as exc:
            raise MessageError('Could not decrypt payload') from exc


class ServerHelloMessage(OutgoingMessage):
    type = MessageType.server_hello  # type: ClassVar[MessageType]
    encrypted = False  # type: ClassVar[bool]

    @classmethod
    def create(
            cls,
            server_public_key: ServerPublicPermanentKey,
    ) -> 'ServerHelloMessage':
        return cls(SERVER_ADDRESS, SERVER_ADDRESS, {
            'type': cls.type.value,
            'key': server_public_key,
        })


class ClientHelloMessage(IncomingMessage):
    type = MessageType.client_hello  # type: ClassVar[MessageType]
    encrypted = False  # type: ClassVar[bool]

    @classmethod
    def from_payload(
            cls,
            payload: Payload,
    ) -> 'ClientHelloMessage':
        """
        MessageError
        """
        payload['key'] = payload.get('key')
        validate_public_key(payload['key'])
        return ClientHelloMessage(SERVER_ADDRESS, SERVER_ADDRESS, payload)

    @property
    def client_public_key(self) -> ClientPublicKey:
        return cast(ClientPublicKey, self.payload['key'])


class ClientAuthMessage(IncomingMessage):
    type = MessageType.client_auth  # type: ClassVar[MessageType]
    encrypted = True  # type: ClassVar[bool]

    @classmethod
    def from_payload(
            cls,
            payload: Payload,
    ) -> 'ClientAuthMessage':
        """
        MessageError
        """
        validate_cookie(payload.get('your_cookie'))
        validate_subprotocols(payload.get('subprotocols'))
        ping_interval = payload.get('ping_interval')
        if ping_interval is not None:
            validate_ping_interval(ping_interval)
        server_key = payload.get('your_key')
        if server_key is not None:
            validate_public_key(server_key)
        return ClientAuthMessage(SERVER_ADDRESS, SERVER_ADDRESS, payload)

    @property
    def server_cookie(self) -> ServerCookie:
        return cast(ServerCookie, self.payload['your_cookie'])

    @property
    def subprotocols(self) -> ListOrTuple[ChosenSubProtocol]:
        return cast(ListOrTuple[ChosenSubProtocol], self.payload['subprotocols'])

    @property
    def ping_interval(self) -> Optional[PingInterval]:
        return cast(Optional[PingInterval], self.payload.get('ping_interval'))

    @property
    def server_key(self) -> Optional[ServerPublicPermanentKey]:
        return cast(Optional[ServerPublicPermanentKey], self.payload.get('your_key'))


class ServerAuthMessage(OutgoingMessage):
    type = MessageType.server_auth  # type: ClassVar[MessageType]
    encrypted = True  # type: ClassVar[bool]

    @classmethod
    def create(
            cls,
            destination: ClientAddress,
            client_cookie: ClientCookie,
            sign_keys: Optional[bool] = False,
            initiator_connected: Optional[bool] = None,
            responder_ids: Optional[ListOrTuple[ResponderAddress]] = None,
    ) -> 'ServerAuthMessage':
        payload = {
            'type': cls.type.value,
            'your_cookie': client_cookie,
        }
        if initiator_connected is not None and responder_ids is not None:
            raise MessageError(('`initiator_connected` and `responder_ids` are '
                                'mutually exclusive'))
        if initiator_connected is not None:
            payload['initiator_connected'] = initiator_connected
        if responder_ids is not None:
            payload['responders'] = responder_ids
        return cls(SERVER_ADDRESS, destination, payload, extra={'sign_keys': sign_keys})

    def prepare_payload(self, client: 'PathClient', nonce: Nonce) -> None:
        """
        Late-signing of the keys.

        Raises :exc:`MessageError` in case the keys could not be
        signed.
        """
        if self.extra.get('sign_keys', False):
            self.payload['signed_keys'] = sign_keys_(client, nonce)


class NewInitiatorMessage(OutgoingMessage):
    type = MessageType.new_initiator  # type: ClassVar[MessageType]
    encrypted = True  # type: ClassVar[bool]

    @classmethod
    def create(cls, destination: ResponderAddress) -> 'NewInitiatorMessage':
        return cls(SERVER_ADDRESS, destination, {
            'type': cls.type.value,
        })


class NewResponderMessage(OutgoingMessage):
    type = MessageType.new_responder  # type: ClassVar[MessageType]
    encrypted = True  # type: ClassVar[bool]

    @classmethod
    def create(cls, responder_id: Address) -> 'NewResponderMessage':
        return cls(SERVER_ADDRESS, INITIATOR_ADDRESS, {
            'type': cls.type.value,
            'id': responder_id,
        })


class DropResponderMessage(IncomingMessage):
    type = MessageType.drop_responder  # type: ClassVar[MessageType]
    encrypted = True  # type: ClassVar[bool]

    @classmethod
    def from_payload(cls, payload: Payload) -> 'DropResponderMessage':
        """
        MessageError
        """
        payload['id'] = validate_responder_id(payload.get('id'))
        payload['reason'] = validate_drop_reason(payload.get('reason'))
        return DropResponderMessage(INITIATOR_ADDRESS, SERVER_ADDRESS, payload)

    @property
    def responder_id(self) -> ResponderAddress:
        return cast(ResponderAddress, self.payload['id'])

    @property
    def reason(self) -> DropReason:
        return cast(DropReason, self.payload['reason'])


class SendErrorMessage(OutgoingMessage):
    type = MessageType.send_error  # type: ClassVar[MessageType]
    encrypted = True  # type: ClassVar[bool]

    @classmethod
    def create(
            cls,
            destination: Address,
            message_id: MessageId,
    ) -> 'SendErrorMessage':
        return cls(SERVER_ADDRESS, destination, {
            'type': cls.type.value,
            'id': message_id,
        })


class DisconnectedMessage(OutgoingMessage):
    type = MessageType.disconnected  # type: ClassVar[MessageType]
    encrypted = True  # type: ClassVar[bool]

    @classmethod
    def create(
            cls,
            destination: ClientAddress,
            client_id: ClientAddress,
    ) -> 'DisconnectedMessage':
        return cls(SERVER_ADDRESS, destination, {
            'type': cls.type.value,
            'id': client_id,
        })
