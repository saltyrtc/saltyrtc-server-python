from typing import (
    Optional,
    Tuple,
    Union,
)

from .base import BaseKey


class PublicKey(BaseKey):
    def __init__(self, pk: bytes) -> None: ...

class SecretKey(BaseKey):
    sk: bytes
    pk: bytes
    def __init__(self, sk: Optional[bytes] = None) -> None: ...

class Box:
    def __init__(self, sk: SecretKey, pk: Union[PublicKey, bytes]) -> None: ...
    def encrypt(
            self, msg: bytes,
            nonce: Optional[bytes] = None,
            pack_nonce: Optional[bool] = True
    ) -> Union[bytes, Tuple[bytes, bytes]]: ...
    def decrypt(
            self, ctxt: bytes,
            nonce: Optional[bytes] = None
    ) -> bytes: ...
