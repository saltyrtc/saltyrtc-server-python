import abc
import struct
import io

import umsgpack

from .exception import *
from .common import ReceiverType, MessageType


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

    @abc.abstractmethod
    def prepare_payload(self, client):
        """
        MessageError
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
    keys_required = None

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
            MessageType.client_hello: NotImplementedError,
            MessageType.client_auth: NotImplementedError,
            MessageType.server_auth: NotImplementedError,
            MessageType.new_responder: NotImplementedError,
            MessageType.drop_responder: NotImplementedError,
            MessageType.send_error: NotImplementedError,
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

        # Get payload and pack
        payload = self.prepare_payload(client)
        try:
            payload = umsgpack.unpack(payload)
        except umsgpack.UnpackException as exc:
            raise MessageError('Could not pack msgpack payload') from exc

        # Encrypt payload if required
        if self.encrypted:
            if not client.box_ready:
                raise MessageFlowError('Cannot encrypt payload, no box available')
            try:
                payload = client.box.encrypt(payload)
            except ValueError as exc:
                raise MessageError('Could not encrypt payload') from exc

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
            if client.box_ready:
                try:
                    payload = client.box.decrypt(payload)
                except ValueError as exc:
                    raise MessageError('Could not decrypt payload') from exc
        else:
            # Is the client allowed to send messages to other peers at the moment?
            if client.p2p_allowed(receiver_type):
                return RawMessage(receiver, receiver_type, payload)
            else:
                raise MessageFlowError('Currently not allowed to dispatch P2P messages')

        # Unpack payload
        try:
            payload = umsgpack.unpack(io.BytesIO(payload))
        except umsgpack.UnpackException as exc:
            raise MessageError('Could not unpack msgpack payload') from exc

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

    @classmethod
    def _check_keys(cls, keys_required, payload):
        missing_keys = [key not in payload for key in keys_required]
        if any(missing_keys):
            raise MessageError('Missing values for keys: {}'.format(missing_keys))


class RawMessage(AbstractMessage):
    def __init__(self, receiver, receiver_type, data):
        super().__init__(receiver, receiver_type)
        self._data = data

    def pack(self, client):
        return self._data

    @classmethod
    def unpack(cls, client, data):
        return AbstractBaseMessage.unpack(client, data)

    def prepare_payload(self, client):
        return

    @classmethod
    def check_payload(cls, client, payload):
        return payload


class ServerHelloMessage(AbstractBaseMessage):
    type = MessageType.server_hello
    encrypted = False
    keys_required = {'key', 'm-cookie'}

    @classmethod
    def create(cls, client, my_cookie):
        # noinspection PyCallingNonCallable
        return cls({
            'key': client.key.pk,
            'm-cookie': my_cookie,
        })

    def prepare_payload(self, client):
        self.check_payload(client, self.payload)

    @classmethod
    def check_payload(cls, client, payload):
        cls._check_keys(cls.keys_required, payload)
