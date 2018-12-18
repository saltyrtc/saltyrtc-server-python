import abc
import binascii
import io
import struct

# noinspection PyPackageRequirements
import libnacl
import umsgpack

from .common import sign_keys as sign_keys_
from .common import (
    COOKIE_LENGTH,
    DATA_LENGTH_MIN,
    NONCE_FORMATTER,
    NONCE_LENGTH,
    AddressType,
    ClientState,
    CloseCode,
    MessageType,
    OverflowSentinel,
    validate_client_id,
    validate_cookie,
    validate_drop_reason,
    validate_hash,
    validate_initiator_connected,
    validate_ping_interval,
    validate_public_key,
    validate_responder_id,
    validate_responder_ids,
    validate_signed_keys,
    validate_subprotocols,
)
from .exception import (
    MessageError,
    MessageFlowError,
)

__all__ = (
    'unpack',
    'AbstractMessage',
    'AbstractBaseMessage',
    'RawMessage',
    'ServerHelloMessage',
    'ClientHelloMessage',
    'ClientAuthMessage',
    'ServerAuthMessage',
    'NewInitiatorMessage',
    'NewResponderMessage',
    'DropResponderMessage',
    'SendErrorMessage',
)


def unpack(client, data):
    """
    MessageError
    MessageFlowError
    """
    return AbstractBaseMessage.unpack(client, data)


def _message_representation(class_name, nonce, payload, encrypted=None):
    hex_cookie_length = COOKIE_LENGTH * 2
    nonce_as_hex = binascii.hexlify(nonce).decode('ascii')
    nonce_as_hex = '|'.join((
        nonce_as_hex[:hex_cookie_length],
        nonce_as_hex[hex_cookie_length:hex_cookie_length + 2],
        nonce_as_hex[hex_cookie_length + 2:hex_cookie_length + 4],
        nonce_as_hex[hex_cookie_length + 4:hex_cookie_length + 8],
        nonce_as_hex[hex_cookie_length + 8:]
    ))
    if isinstance(encrypted, bool):
        encrypted_str = 'encrypted={}, '.format(encrypted)
    else:
        encrypted_str = ''
    return '{}({}nonce={}, data={})'.format(
        class_name, encrypted_str, nonce_as_hex, payload)


class AbstractMessage(metaclass=abc.ABCMeta):
    type = None

    def __init__(self, source, destination, source_type=None, destination_type=None):
        if source_type is None:
            AddressType.from_address(source)
        if destination_type is None:
            AddressType.from_address(destination)
        self.source = source
        self.destination = destination
        self.source_type = source_type
        self.destination_type = destination_type
        self._nonce = None

    @abc.abstractmethod
    def pack(self, client):
        """
        MessageError
        MessageFlowError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def prepare_payload(self, client, nonce):
        """
        This method will be called as soon as the nonce has been packed
        to make late changes to the payload based on the nonce.

        Only :exc:`MessageError` may be raised.
        """
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def unpack(cls, client, data):
        """
         MessageError
         MessageFlowError
         """
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        raise NotImplementedError


# noinspection PyAbstractClass
class AbstractBaseMessage(AbstractMessage, metaclass=abc.ABCMeta):
    encrypted = None

    def __new__(cls, payload, *args, **kwargs):
        # Ensure the class has implemented a class-level `type` attribute
        if cls.type not in MessageType:
            message = 'Cannot instantiate class {} with invalid message type: {}'
            raise TypeError(message.format(cls.__name__, cls.type))

        # Ensure the class has implemented a class-level `encrypted` flag
        if cls.encrypted is not True and cls.encrypted is not False:
            message = 'Cannot instantiate class {} with invalid encrypted flag: {}'
            raise TypeError(message.format(cls.__name__, cls.encrypted))

        return super().__new__(cls)

    def __init__(
            self, source, destination, payload,
            source_type=None, destination_type=None, extra=None
    ):
        super().__init__(
            source, destination,
            source_type=source_type, destination_type=destination_type
        )
        self.payload = {} if payload is None else payload
        self.extra = {} if extra is None else extra

    def __str__(self):
        return _message_representation(
            self.__class__.__name__, self._nonce, self.payload, encrypted=self.encrypted)

    @classmethod
    def _get_message_classes(cls):
        if getattr(cls, '_message_classes', None) is None:
            cls._message_classes = {
                MessageType.server_hello: ServerHelloMessage,
                MessageType.client_hello: ClientHelloMessage,
                MessageType.client_auth: ClientAuthMessage,
                MessageType.server_auth: ServerAuthMessage,
                MessageType.new_responder: NewResponderMessage,
                MessageType.drop_responder: DropResponderMessage,
                MessageType.send_error: SendErrorMessage,
            }
        return cls._message_classes

    def pack(self, client):
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
        payload = self._pack_payload()

        # Encrypt payload if required
        if self.encrypted:
            if client.state != ClientState.authenticated:
                raise MessageFlowError('Cannot encrypt payload, not authenticated')
            payload = self._encrypt_payload(client, nonce, payload)

        # Append payload and return as bytes
        data.write(payload)
        return data.getvalue()

    def prepare_payload(self, client, nonce):
        return

    @classmethod
    def unpack(cls, client, data):
        """
        MessageError
        MessageFlowError
        """
        # Check length
        length = len(data)
        if length < DATA_LENGTH_MIN:
            raise MessageError('Message too short: {} bytes'.format(length))

        # Unpack and check nonce
        (nonce,
         source, source_type,
         destination, destination_type) = cls._unpack_nonce(data, client)

        # Decrypt if directed at us and keys have been exchanged
        # or just return a raw message to be sent to another client
        expect_type = None
        if destination_type == AddressType.server:
            data = data[NONCE_LENGTH:]
            if client.state == ClientState.restricted and client.type is None:
                payload = None

                # Try client-auth (encrypted)
                try:
                    payload = cls._unpack_payload(
                        cls._decrypt_payload(client, nonce, data))
                except MessageError:
                    pass
                else:
                    expect_type = MessageType.client_auth

                # Try client-hello (unencrypted)
                if payload is None:
                    try:
                        payload = cls._unpack_payload(data)
                    except MessageError:
                        payload = None
                    else:
                        expect_type = MessageType.client_hello

                # Still no payload?
                if expect_type is None or payload is None:
                    message = 'Expected either client-hello or client-auth, got neither'
                    raise MessageError(message)
            else:
                # Decrypt and unpack payload
                payload = cls._unpack_payload(
                    cls._decrypt_payload(client, nonce, data))
        else:
            message = RawMessage(
                source, destination, data,
                source_type=source_type, destination_type=destination_type
            )
            message._nonce = nonce  # Stored for str representation
            return message

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

        # Ensure type isn't violated
        if expect_type is not None and type_ != expect_type:
            raise MessageError('Expected type {}, got {}'.format(expect_type, type_))

        # Check and convert payload on appropriate message class
        try:
            message_class = cls._get_message_classes()[type_]
        except KeyError as exc:
            error_message = 'Can not handle valid message type: {}'
            raise MessageError(error_message.format(type_)) from exc
        payload = message_class.check_payload(client, payload)

        # Return instance
        message = message_class(
            source, destination, payload,
            source_type=source_type, destination_type=destination_type
        )
        message._nonce = nonce  # Stored for str representation
        return message

    def _pack_nonce(self, client):
        """
        .. note:: The CSN check and incrementation can only reside here
                  because an error while packing a message will
                  create a protocol error in any case.

        MessageError
        MessageFlowError
        """
        # Ensure that the outgoing combined sequence number counter did not overflow
        if client.combined_sequence_number_out == OverflowSentinel:
            raise MessageFlowError(('Cannot send any more messages, due to a sequence '
                                    'number counter overflow'))

        # Pack nonce
        try:
            nonce = struct.pack(
                NONCE_FORMATTER,
                client.cookie_out,
                self.source, self.destination,
                struct.pack('!Q', client.combined_sequence_number_out)[2:]
            )
        except struct.error as exc:
            raise MessageError('Could not pack nonce') from exc

        # Increase outgoing combined sequence number counter
        client.combined_sequence_number_out += 1
        return nonce

    @classmethod
    def _unpack_nonce(cls, data, client):
        """
        .. note:: The CSN check and incrementation can only reside here
                  because an error while unpacking a message will
                  create a protocol error in any case.

        MessageError
        MessageFlowError
        """
        nonce = data[:NONCE_LENGTH]
        try:
            (cookie_in,
             source, destination,
             combined_sequence_number_in) = struct.unpack(NONCE_FORMATTER, nonce)
            combined_sequence_number_in, *_ = struct.unpack(
                '!Q', b'\x00\x00' + combined_sequence_number_in)
        except struct.error as exc:
            raise MessageError('Could not unpack nonce') from exc

        # Get source and destination address type
        source_type = AddressType.from_address(source)
        destination_type = AddressType.from_address(destination)

        # Validate destination
        # (Is the client allowed to send messages to the address type?)
        is_to_server = destination_type == AddressType.server
        if not is_to_server and not client.p2p_allowed(destination_type):
            error = 'Not allowed to relay messages to 0x{:02x}'
            raise MessageFlowError(error.format(destination_type))

        # Validate source
        if source != client.id:
            error_message = 'Identities do not match, expected 0x{:02x}, got 0x{:02x}'
            raise MessageError(error_message.format(client.id, source))

        # Validate cookie
        if is_to_server and not client.valid_cookie(cookie_in):
            raise MessageError('Invalid cookie: {}'.format(cookie_in))

        # Validate and increase combined sequence number
        if is_to_server:
            client.validate_combined_sequence_number(combined_sequence_number_in)
            client.combined_sequence_number_in += 1

        return nonce, source, source_type, destination, destination_type

    def _pack_payload(self):
        try:
            return umsgpack.packb(self.payload)
        except umsgpack.PackException as exc:
            raise MessageError('Could not pack msgpack payload') from exc

    @classmethod
    def _unpack_payload(cls, payload):
        try:
            return umsgpack.unpackb(payload)
        except (umsgpack.UnpackException, TypeError) as exc:
            raise MessageError('Could not unpack msgpack payload') from exc

    @classmethod
    def _encrypt_payload(cls, client, nonce, payload):
        try:
            _, data = client.box.encrypt(payload, nonce=nonce, pack_nonce=False)
            return data
        except (ValueError, libnacl.CryptError) as exc:
            raise MessageError('Could not encrypt payload') from exc

    @classmethod
    def _decrypt_payload(cls, client, nonce, data):
        try:
            return client.box.decrypt(data, nonce=nonce)
        except (ValueError, libnacl.CryptError) as exc:
            raise MessageError('Could not decrypt payload') from exc


class RawMessage(AbstractMessage):
    type = 'raw'  # Note: This field is used for logging purposes only

    def __init__(
            self, source, destination, data,
            source_type=None, destination_type=None
    ):
        super().__init__(
            source, destination,
            source_type=source_type, destination_type=destination_type
        )
        self._data = data

    def __str__(self):
        return _message_representation(
            self.__class__.__name__, self._nonce, self._data)

    def pack(self, client):
        return self._data

    def prepare_payload(self, client, nonce):
        return

    @classmethod
    def unpack(cls, client, data):
        return AbstractBaseMessage.unpack(client, data)

    @classmethod
    def check_payload(cls, client, payload):
        pass


class ServerHelloMessage(AbstractBaseMessage):
    type = MessageType.server_hello
    encrypted = False

    @classmethod
    def create(cls, source, destination, server_public_key):
        # noinspection PyCallingNonCallable
        return cls(source, destination, {
            'type': cls.type.value,
            'key': server_public_key,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        payload['key'] = payload.get('key')
        validate_public_key(payload['key'])
        return payload

    @property
    def server_public_key(self):
        return self.payload['key']


class ClientHelloMessage(AbstractBaseMessage):
    type = MessageType.client_hello
    encrypted = False

    @classmethod
    def create(cls, source, destination, client_public_key):
        # noinspection PyCallingNonCallable
        return cls(source, destination, {
            'type': cls.type.value,
            'key': client_public_key,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        payload['key'] = payload.get('key')
        validate_public_key(payload['key'])
        return payload

    @property
    def client_public_key(self):
        return self.payload['key']


class ClientAuthMessage(AbstractBaseMessage):
    type = MessageType.client_auth
    encrypted = True

    @classmethod
    def create(
            cls, source, destination, server_cookie, subprotocols,
            ping_interval=None, server_key=None):
        # noinspection PyCallingNonCallable
        payload = {
            'type': cls.type.value,
            'your_cookie': server_cookie,
            'subprotocols': subprotocols,
        }
        if ping_interval is not None:
            payload['ping_interval'] = ping_interval
        if server_key is not None:
            payload['your_key'] = server_key
        return cls(source, destination, payload)

    @classmethod
    def check_payload(cls, client, payload):
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
        return payload

    @property
    def server_cookie(self):
        return self.payload['your_cookie']

    @property
    def subprotocols(self):
        return self.payload['subprotocols']

    @property
    def ping_interval(self):
        return self.payload.get('ping_interval')

    @property
    def server_key(self):
        return self.payload.get('your_key')


class ServerAuthMessage(AbstractBaseMessage):
    type = MessageType.server_auth
    encrypted = True

    @classmethod
    def create(
            cls, source, destination, client_cookie,
            sign_keys=False, initiator_connected=None, responder_ids=None
    ):
        payload = {
            'type': cls.type.value,
            'your_cookie': client_cookie,
        }
        if initiator_connected is not None:
            payload['initiator_connected'] = initiator_connected
        if responder_ids is not None:
            payload['responders'] = responder_ids
        # noinspection PyCallingNonCallable
        return cls(source, destination, payload, extra={'sign_keys': sign_keys})

    def prepare_payload(self, client, nonce):
        """
        Late-signing of the keys.

        Raises :exc:`MessageError` in case the keys could not be
        signed.
        """
        if self.extra.get('sign_keys', False):
            self.payload['signed_keys'] = sign_keys_(client, nonce)

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_cookie(payload.get('your_cookie'))
        signed_keys = payload.get('signed_keys')
        if signed_keys is not None:
            validate_signed_keys(signed_keys)
        responders = payload.get('responders')
        if responders is not None:
            validate_responder_ids(responders)
        initiator_connected = payload.get('initiator_connected')
        if initiator_connected is not None:
            validate_initiator_connected(initiator_connected)
        return payload

    @property
    def client_cookie(self):
        return self.payload['your_cookie']

    @property
    def signed_keys(self):
        """
        KeyError in case the message contains no 'signed_keys' field.
        """
        return self.payload['signed_keys']

    @property
    def initiator_connected(self):
        """
        KeyError in case the message is directed at an initiator.
        """
        return self.payload['initiator_connected']

    @property
    def responder_ids(self):
        """
        KeyError in case the message is directed at a responder.
        """
        return self.payload['responders']


class NewInitiatorMessage(AbstractBaseMessage):
    type = MessageType.new_initiator
    encrypted = True

    @classmethod
    def create(cls, source, destination):
        # noinspection PyCallingNonCallable
        return cls(source, destination, {
            'type': cls.type.value,
        })

    @classmethod
    def check_payload(cls, client, payload):
        return payload


class NewResponderMessage(AbstractBaseMessage):
    type = MessageType.new_responder
    encrypted = True

    @classmethod
    def create(cls, source, destination, responder_id):
        # noinspection PyCallingNonCallable
        return cls(source, destination, {
            'type': cls.type.value,
            'id': responder_id,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_responder_id(payload.get('id'))
        return payload

    @property
    def responder_id(self):
        return self.payload['id']


class DropResponderMessage(AbstractBaseMessage):
    type = MessageType.drop_responder
    encrypted = True

    @classmethod
    def create(cls, source, destination, responder_id, reason=None):
        if reason is None:
            reason = CloseCode.drop_by_initiator
        # noinspection PyCallingNonCallable
        return cls(source, destination, {
            'type': cls.type.value,
            'id': responder_id,
            'reason': reason.value
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_responder_id(payload.get('id'))
        payload['reason'] = validate_drop_reason(payload.get('reason'))
        return payload

    @property
    def responder_id(self):
        return self.payload['id']

    @property
    def reason(self):
        return self.payload['reason']


class SendErrorMessage(AbstractBaseMessage):
    type = MessageType.send_error
    encrypted = True

    @classmethod
    def create(cls, source, destination, message_id):
        # noinspection PyCallingNonCallable
        return cls(source, destination, {
            'type': cls.type.value,
            'id': message_id,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_hash(payload.get('hash'))
        return payload

    @property
    def message_hash(self):
        return self.payload['hash']


class DisconnectedMessage(AbstractBaseMessage):
    type = MessageType.disconnected
    encrypted = True

    @classmethod
    def create(cls, source, destination, client_id):
        # noinspection PyCallingNonCallable
        return cls(source, destination, {
            'type': cls.type.value,
            'id': client_id,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_client_id(payload.get('id'))
        return payload

    @property
    def client_id(self):
        return self.payload['id']
