from typing import (
    Any,
    List,
    Optional,
    Tuple,
    Union,
)

import pytest

from saltyrtc.server import (
    DEFAULT_DROP_REASON,
    INITIATOR_ADDRESS,
    SERVER_ADDRESS,
    Address,
    AddressType,
    ClientAddress,
    CloseCode,
    DropReason,
    InitiatorAddress,
    MessageError,
    ResponderAddress,
    ServerAddress,
    validate_drop_reason,
    validate_responder_id,
    validate_subprotocol,
    validate_subprotocols,
)


class TestDropReason:
    """
    A drop reason must be a :class:`CloseCode` (or an integer when
    parsed) and be allowed as a drop reason.
    """
    invalid_reasons = [
        '1',
        b'\x01',
        'meow',
        float(3.3333),
        None,
        object(),
        999,
        1001,
        3000,
    ]  # type: List[Any]
    valid_reasons = list(DropReason)  # type: List[DropReason]

    @pytest.mark.parametrize('reason', invalid_reasons)
    def test_invalid_reason(self, reason: Any) -> None:
        with pytest.raises(ValueError) as exc_info:
            DropReason(reason)
        assert 'is not a valid DropReason' in str(exc_info.value)

    def test_default_reason(self):
        assert DEFAULT_DROP_REASON == DropReason.drop_by_initiator

    @pytest.mark.parametrize('reason', valid_reasons)
    def test_reason_is_valid_close_code(self, reason: DropReason) -> None:
        CloseCode(reason)

    @pytest.mark.parametrize('reason', [reason for reason in invalid_reasons
                                        if reason is not None])
    def test_received_invalid_reason(self, reason: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_drop_reason(reason)
        assert 'Invalid drop reason' in str(exc_info.value)

    @pytest.mark.parametrize('reason', valid_reasons + [None])
    def test_received_valid_reason(self, reason: Optional[int]) -> None:
        assert isinstance(validate_drop_reason(reason), DropReason)


class TestAddress:
    """
    An address must be in the valid range of SaltyRTC addresses.
    """
    invalid_addresses = [
        '1',
        b'\x01',
        'meow',
        float(3.3333),
        None,
        object(),
        -1,
        0x100,
    ]  # type: List[Any]
    valid_addresses = [0x00, 0x01, 0x02, 0x30, 0xff]  # type: List[int]
    addresses_type_mapping = [
        (0x00, AddressType.server),
        (0x01, AddressType.initiator),
        (0x02, AddressType.responder),
        (0x30, AddressType.responder),
        (0xff, AddressType.responder),
    ]

    @pytest.mark.parametrize('address', invalid_addresses)
    def test_invalid_address(self, address: Any) -> None:
        with pytest.raises(ValueError) as exc_info:
            Address(address)
        assert 'Invalid address' in str(exc_info.value)

    @pytest.mark.parametrize('address', valid_addresses)
    def test_valid_address_equality(self, address: int) -> None:
        assert Address(address) == address

    @pytest.mark.parametrize('address,expected', addresses_type_mapping)
    def test_to_type(self, address: int, expected: AddressType) -> None:
        address = Address(address)
        assert address.type == expected


class TestServerAddress:
    """
    A server address must be exactly 0x00.
    """
    def test_create(self) -> None:
        assert ServerAddress() == SERVER_ADDRESS

    def test_equality(self) -> None:
        assert SERVER_ADDRESS == 0x00
        assert SERVER_ADDRESS == Address(0x00)


class TestClientAddress:
    """
    A client address must be an integer in the valid range of client
    ids (0x01..0xff).
    """
    invalid_addresses = TestAddress.invalid_addresses + [0x00]  # type: List[Any]
    valid_addresses = [0x01, 0x02, 0x30, 0xff]  # type: List[int]

    @pytest.mark.parametrize('address', invalid_addresses)
    def test_invalid_address(self, address: Any) -> None:
        with pytest.raises(ValueError) as exc_info:
            ClientAddress(address)
        assert 'Invalid address' in str(exc_info.value)

    @pytest.mark.parametrize('address', valid_addresses)
    def test_valid_address_equality(self, address: int) -> None:
        assert ClientAddress(address) == address


class TestInitiatorAddress:
    """
    An initiator address must be exactly 0x01.
    """
    def test_create(self) -> None:
        assert InitiatorAddress() == INITIATOR_ADDRESS

    def test_equality(self) -> None:
        assert INITIATOR_ADDRESS == 0x01
        assert INITIATOR_ADDRESS == Address(0x01)
        assert INITIATOR_ADDRESS == ClientAddress(0x01)

    def test_to_type(self) -> None:
        assert INITIATOR_ADDRESS.type == AddressType.initiator


class TestResponderAddress:
    """
    A responder address must be an integer in the valid range of
    responder ids (0x02..0xff).
    """
    invalid_addresses = TestAddress.invalid_addresses + [0x00, 0x01]  # type: List[Any]
    valid_addresses = [0x02, 0x30, 0xff]  # type: List[int]

    @pytest.mark.parametrize('address', invalid_addresses)
    def test_invalid_address(self, address: Any) -> None:
        with pytest.raises(ValueError) as exc_info:
            ResponderAddress(address)
        assert 'Invalid address' in str(exc_info.value)

    @pytest.mark.parametrize('address', valid_addresses)
    def test_valid_address_equality(self, address: int) -> None:
        assert ResponderAddress(address) == address

    @pytest.mark.parametrize('id_', valid_addresses)
    def test_received_invalid_id(self, id_: int) -> None:
        validate_responder_id(id_)

    @pytest.mark.parametrize('id_', invalid_addresses)
    def test_received_valid_id(self, id_: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_responder_id(id_)
        assert 'Invalid responder id' in str(exc_info.value)


class TestSubprotocol:
    """
    A sub-protocol must be a string.
    """
    invalid_subprotocols = [b'h3h3', 1, float(3.3333)]  # type: List[any]
    valid_subprotocols = ['', 'kittie-protocol-3000']  # type: List[str]

    @pytest.mark.parametrize('subprotocol', invalid_subprotocols)
    def test_received_invalid_subprotocol(self, subprotocol: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_subprotocol(subprotocol)
        assert 'Invalid sub-protocol' in str(exc_info.value)

    @pytest.mark.parametrize('subprotocol', valid_subprotocols)
    def test_received_valid_subprotocol(self, subprotocol: str) -> None:
        validate_subprotocol(subprotocol)


class TestSubprotocols:
    """
    A sub-protocol must contain a list of strings.
    """
    not_list_like = (TestSubprotocol.valid_subprotocols +
                     TestSubprotocol.invalid_subprotocols)  # type: List[Any]
    invalid_subprotocols_list = [TestSubprotocol.invalid_subprotocols]

    @pytest.mark.parametrize('subprotocols', not_list_like)
    def test_received_invalid_not_list_like(self, subprotocols: Any) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_subprotocols(subprotocols)
        assert 'Sub-protocols not list or tuple' in str(exc_info.value)

    @pytest.mark.parametrize('subprotocols', invalid_subprotocols_list)
    def test_received_invalid_subprotocols(
            self,
            subprotocols: Union[List[Any], Tuple[Any]],
    ) -> None:
        with pytest.raises(MessageError) as exc_info:
            validate_subprotocols(subprotocols)
        assert 'Invalid sub-protocol' in str(exc_info.value)

    @pytest.mark.parametrize('subprotocols', [
        tuple(TestSubprotocol.valid_subprotocols),
        list(TestSubprotocol.valid_subprotocols)
    ])
    def test_received_valid_subprotocols(
            self,
            subprotocols: Union[List[str], Tuple[str]],
    ) -> None:
        validate_subprotocols(subprotocols)
