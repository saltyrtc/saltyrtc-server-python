from typing import (
    Any,
    List,
    Tuple,
    Union,
)

import pytest

from saltyrtc.server import (
    MessageError,
    validate_client_id,
    validate_responder_id,
    validate_responder_ids,
    validate_subprotocol,
    validate_subprotocols,
)

valid_subprotocols = ['', 'kittie-protocol-3000']
valid_client_ids = [0x01, 0x30, 0xff]
valid_responder_ids = [0x02, 0x30, 0xff]
invalid_subprotocols = [b'h3h3', 1, float(3.3333)]
invalid_client_ids = [
    b'\x01',
    'meow',
    float(3.3333),
    None,
    object(),
    0x00,
    0x100,
]
invalid_responder_ids = invalid_client_ids + [0x01]


class TestSubprotocol:
    """
    A sub-protocol must be a string.
    """
    @pytest.mark.parametrize('subprotocol', invalid_subprotocols)
    def test_invalid_subprotocol(self, subprotocol: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_subprotocol(subprotocol)
        assert 'Invalid sub-protocol' in str(exc_info.value)

    @pytest.mark.parametrize('subprotocol', valid_subprotocols)
    def test_valid_subprotocol(self, subprotocol: str) -> None:
        validate_subprotocol(subprotocol)


class TestSubprotocols:
    """
    A sub-protocol must contain a list of strings.
    """
    @pytest.mark.parametrize('subprotocols', valid_subprotocols + invalid_subprotocols)
    def test_invalid_not_list_like(self, subprotocols: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_subprotocols(subprotocols)
        assert 'Sub-protocols not list or tuple' in str(exc_info.value)

    @pytest.mark.parametrize('subprotocols', [invalid_subprotocols])
    def test_invalid_ids(self, subprotocols: Union[List[Any], Tuple[Any]]):
        with pytest.raises(MessageError) as exc_info:
            validate_subprotocols(subprotocols)
        assert 'Invalid sub-protocol' in str(exc_info.value)

    @pytest.mark.parametrize('subprotocols', [
        tuple(valid_subprotocols),
        list(valid_subprotocols)
    ])
    def test_valid_ids(self, subprotocols: Union[List[str], Tuple[str]]) -> None:
        validate_subprotocols(subprotocols)


class TestClientId:
    """
    A client id must be an integer in the valid range of client ids.
    """
    @pytest.mark.parametrize('id_', invalid_client_ids)
    def test_invalid_id(self, id_: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_client_id(id_)
        assert 'Invalid client id' in str(exc_info.value)

    @pytest.mark.parametrize('id_', valid_client_ids)
    def test_valid_id(self, id_: int) -> None:
        validate_client_id(id_)


class TestResponderId:
    """
    A responder id must be an integer in the valid range of responder
    ids.
    """
    @pytest.mark.parametrize('id_', invalid_responder_ids)
    def test_invalid_id(self, id_: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_responder_id(id_)
        assert 'Invalid responder id' in str(exc_info.value)

    @pytest.mark.parametrize('id_', valid_responder_ids)
    def test_valid_id(self, id_: int) -> None:
        validate_responder_id(id_)


class TestResponderIds:
    """
    Responder ids must be a list or tuple of ids in the valid range of
    responder ids.
    """
    @pytest.mark.parametrize('ids', valid_responder_ids + invalid_responder_ids)
    def test_invalid_not_list_like(self, ids: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_responder_ids(ids)
        assert 'Responder ids not list or tuple' in str(exc_info.value)

    @pytest.mark.parametrize('ids', [invalid_responder_ids])
    def test_invalid_ids(self, ids: Union[List[Any], Tuple[Any]]):
        with pytest.raises(MessageError) as exc_info:
            validate_responder_ids(ids)
        assert 'Invalid responder id' in str(exc_info.value)

    @pytest.mark.parametrize('ids', [
        tuple(valid_responder_ids),
        list(valid_responder_ids)
    ])
    def test_valid_ids(self, ids: Union[List[int], Tuple[int]]) -> None:
        validate_responder_ids(ids)
