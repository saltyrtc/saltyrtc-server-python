import abc
import struct
import io

import umsgpack

from .exception import *
from .common import (
    ReceiverType, MessageType,
    validate_public_key, validate_cookie, validate_responder, validate_responder_list,
    validate_hash,
)


def unpack(client, data):
    """
    MessageError
    MessageFlowError
    """
    return AbstractBaseMessage.unpack(client, data)


class AbstractMessage(metaclass=abc.ABCMeta):
    def __init__(self, receiver, receiver_type):
        self.receiver = receiver
        self.receiver_type = receiver_type

    @abc.abstractmethod
    def pack(self, client):
        """
        MessageError
        MessageFlowError
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


class AbstractBaseMessage(AbstractMessage, metaclass=abc.ABCMeta):
    type = None
    encrypted = None

    def __new__(
            cls, payload, *args,
            receiver=ReceiverType.server.value, receiver_type=None, **kwargs
    ):
        # Ensure the class has implemented a class-level `type` attribute
        if cls.type not in MessageType:
            message = 'Cannot instantiate class {} with invalid message type: {}'
            raise TypeError(message.format(cls.__name__, cls.type))
        # Ensure the class has implemented a class-level `encrypted` flag
        if cls.encrypted is not True and cls.encrypted is not False:
            message = 'Cannot instantiate class {} with invalid encrypted flag: {}'
            raise TypeError(message.format(cls.__name__, cls.encrypted))

        # Set message classes and if encryption is required for them
        cls._message_classes = {
            MessageType.server_hello: ServerHelloMessage,
            MessageType.client_hello: ClientHelloMessage,
            MessageType.client_auth: ClientAuthMessage,
            MessageType.server_auth: ServerAuthMessage,
            MessageType.new_responder: NewResponderMessage,
            MessageType.drop_responder: DropResponderMessage,
            MessageType.send_error: SendErrorMessage,
        }

        return super().__new__(cls)

    def __init__(self, payload, receiver=ReceiverType.server.value, receiver_type=None):
        if receiver_type is None:
            receiver_type = ReceiverType.from_receiver(receiver)
        super().__init__(receiver, receiver_type)
        self.payload = {} if payload is None else payload

    def pack(self, client):
        """
        MessageError
        MessageFlowError
        """
        data = io.BytesIO()

        # Check receiver type
        is_from_server = self.receiver_type == ReceiverType.server
        if not is_from_server and not client.p2p_allowed(self.receiver_type):
            raise MessageFlowError('Currently not allowed to dispatch P2P messages')

        # Pack receiver byte
        data.write(self._pack_receiver())

        # Pack payload
        payload = self._pack_payload()

        # Encrypt payload if required
        if self.encrypted:
            if not client.authenticated:
                raise MessageFlowError('Cannot encrypt payload, no box available')
            payload = self._encrypt_payload(client, payload)

        # Append payload and return as bytes
        data.write(payload)
        return data.getvalue()

    @classmethod
    def unpack(cls, client, data):
        """
        MessageError
        MessageFlowError
        """
        receiver, receiver_type = cls._unpack_receiver(data)

        # Decrypt if directed at us and keys have been exchanged
        # or just return a raw message to be sent to another client
        payload = data[1:]
        if receiver_type == ReceiverType.server:
            if not client.authenticated:
                payload = None

                # Try client-hello (unencrypted)
                try:
                    payload = cls._unpack_payload(payload)
                except MessageError:
                    pass

                # Try client-auth (encrypted)
                try:
                    payload = cls._unpack_payload(cls._decrypt_payload(client, payload))
                except MessageError:
                    pass

                # Still no payload?
                if payload is None:
                    message = 'Expected either client-hello or client-auth, got neither'
                    raise MessageError(message)

            else:
                # Decrypt and unpack payload
                payload = cls._unpack_payload(cls._decrypt_payload(client, payload))
        else:
            # Is the client allowed to send messages to the receiver type?
            if client.p2p_allowed(receiver_type):
                return RawMessage(receiver, receiver_type, payload)
            else:
                raise MessageFlowError('Currently not allowed to dispatch P2P messages')

        # Unpack type
        type_ = payload.get('type')
        try:
            type_ = MessageType(type_)
        except ValueError as exc:
            raise MessageError('Unknown message type: {}'.format(type_)) from exc

        # Check and convert payload on appropriate message class
        message_class = cls._message_classes[type_]
        message_class.check_payload(client, payload)

        # Return instance
        return message_class(receiver, payload, receiver_type=receiver_type)

    def _pack_receiver(self):
        """
        MessageError
        """
        try:
            return struct.pack('!B', self.receiver)
        except struct.error as exc:
            raise MessageError('Could not pack receiver byte') from exc

    @classmethod
    def _unpack_receiver(cls, data):
        """
        MessageError
        """
        try:
            receiver = struct.unpack('!B', data)
        except struct.error as exc:
            raise MessageError('Could not unpack receiver byte') from exc

        # Determine receiver type
        receiver_type = ReceiverType.from_receiver(receiver)
        return receiver, receiver_type

    def _pack_payload(self):
        try:
            return umsgpack.pack(self.payload)
        except umsgpack.PackException as exc:
            raise MessageError('Could not pack msgpack payload') from exc

    @classmethod
    def _unpack_payload(cls, payload):
        try:
            return umsgpack.unpack(io.BytesIO(payload))
        except umsgpack.UnpackException as exc:
            raise MessageError('Could not unpack msgpack payload') from exc

    @classmethod
    def _encrypt_payload(cls, client, payload):
        try:
            return client.box.encrypt(payload)
        except ValueError as exc:
            raise MessageError('Could not encrypt payload') from exc

    @classmethod
    def _decrypt_payload(cls, client, payload):
        try:
            return client.box.decrypt(payload)
        except ValueError as exc:
            raise MessageError('Could not decrypt payload') from exc


class RawMessage(AbstractMessage):
    def __init__(self, receiver, receiver_type, data):
        super().__init__(receiver, receiver_type)
        self._data = data

    def pack(self, client):
        return self._data

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
    def create(cls, server_public_key, server_cookie):
        # noinspection PyCallingNonCallable
        return cls({
            'type': cls.type.value,
            'key': server_public_key,
            'm-cookie': server_cookie,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_public_key(payload.get('key'))
        validate_cookie(payload.get('m-cookie'))


class ClientHelloMessage(AbstractBaseMessage):
    type = MessageType.client_hello
    encrypted = False

    @classmethod
    def create(cls, client_public_key):
        # noinspection PyCallingNonCallable
        return cls({
            'type': cls.type.value,
            'key': client_public_key,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_public_key(payload.get('key'))


class ClientAuthMessage(AbstractBaseMessage):
    type = MessageType.client_auth
    encrypted = True

    @classmethod
    def create(cls, server_cookie, client_cookie):
        # noinspection PyCallingNonCallable
        return cls({
            'type': cls.type.value,
            'y-cookie': server_cookie,
            'm-cookie': client_cookie,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_cookie(payload.get('y-cookie'))
        validate_cookie(payload.get('m-cookie'))


class ServerAuthMessage(AbstractBaseMessage):
    type = MessageType.server_auth
    encrypted = True

    @classmethod
    def create(cls, client_cookie, responders):
        # noinspection PyCallingNonCallable
        return cls({
            'type': cls.type.value,
            'y-cookie': client_cookie,
            'responders': responders,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_responder_list(payload.get('responders'))


class NewResponderMessage(AbstractBaseMessage):
    type = MessageType.new_responder
    encrypted = True

    @classmethod
    def create(cls, responder_id):
        # noinspection PyCallingNonCallable
        return cls({
            'type': cls.type.value,
            'id': responder_id,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_responder(payload.get('id'))


class DropResponderMessage(AbstractBaseMessage):
    type = MessageType.drop_responder
    encrypted = True

    @classmethod
    def create(cls, responder_id):
        # noinspection PyCallingNonCallable
        return cls({
            'type': cls.type.value,
            'id': responder_id,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_responder(payload.get('id'))


class SendErrorMessage(AbstractBaseMessage):
    type = MessageType.send_error
    encrypted = True

    @classmethod
    def create(cls, message_hash):
        # noinspection PyCallingNonCallable
        return cls({
            'type': cls.type.value,
            'hash': message_hash,
        })

    @classmethod
    def check_payload(cls, client, payload):
        """
        MessageError
        """
        validate_hash(payload.get('hash'))
