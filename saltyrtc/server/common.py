import enum


KEY_LENGTH = 32


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


class MessageType(enum.Enum):
    """left out client-to-client message types"""
    server_hello = 'server-hello'
    client_hello = 'client-hello'
    client_auth = 'client-auth'
    server_auth = 'server-auth'
    new_responder = 'new-responder'
    drop_responder = 'drop-responder'
    send_error = 'send-error'
