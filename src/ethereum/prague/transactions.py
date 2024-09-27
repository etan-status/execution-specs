from typing import Optional, Type, Union

import snappy

from remerkleable.basic import uint8, uint64, uint256
from remerkleable.byte_arrays import ByteList, ByteVector, Bytes32
from remerkleable.complex import Container, List
from remerkleable.stable_container import Profile, StableContainer

from ethereum.crypto.elliptic_curve import (
    secp256k1_pack,
    secp256k1_recover_packed,
    secp256k1_unpack,
    secp256k1_validate,
)
from ethereum.crypto.hash import keccak256

from ethereum.exceptions import InvalidBlock

from .. import rlp
from ..base_types import Bytes, U64, U256
from ..exceptions import InvalidBlock
from .fork_types import Address
from .transactions_rlp import (
    AccessListRlpTransaction,
    AnyRlpAuthorization,
    AnyRlpTransaction,
    BlobRlpTransaction,
    FeeMarketRlpTransaction,
    LegacyRlpTransaction,
    SetCodeRlpAuthorization,
    SetCodeRlpTransaction,
    auth_hash_7702,
    signing_hash_155,
    signing_hash_1559,
    signing_hash_2930,
    signing_hash_4844,
    signing_hash_7702,
    signing_hash_pre155,
)

TX_BASE_COST = 21000
TX_DATA_COST_PER_NON_ZERO = 16
TX_DATA_COST_PER_ZERO = 4
TX_CREATE_COST = 32000
TX_ACCESS_LIST_ADDRESS_COST = 2400
TX_ACCESS_LIST_STORAGE_KEY_COST = 1900


class Hash32(Bytes32):
    pass


class ExecutionAddress(ByteVector[20]):
    pass


class VersionedHash(Bytes32):
    pass


SECP256K1_SIGNATURE_SIZE = 32 + 32 + 1
MAX_EXECUTION_SIGNATURE_FIELDS = uint64(2**3)


class ExecutionSignature(StableContainer[MAX_EXECUTION_SIGNATURE_FIELDS]):
    secp256k1: Optional[ByteVector[SECP256K1_SIGNATURE_SIZE]]


class Secp256k1ExecutionSignature(Profile[ExecutionSignature]):
    secp256k1: ByteVector[SECP256K1_SIGNATURE_SIZE]



MAX_FEES_PER_GAS_FIELDS = uint64(2**4)
MAX_CALLDATA_SIZE = uint64(2**24)
MAX_ACCESS_LIST_STORAGE_KEYS = uint64(2**19)
MAX_ACCESS_LIST_SIZE = uint64(2**19)
MAX_BLOB_COMMITMENTS_PER_BLOCK = uint64(2**12)
MAX_AUTHORIZATION_PAYLOAD_FIELDS = uint64(2**4)
MAX_AUTHORIZATION_LIST_SIZE = uint64(2**16)
MAX_TRANSACTION_PAYLOAD_FIELDS = uint64(2**5)


class TransactionType(uint8):
    pass


class ChainId(uint64):
    pass


class FeePerGas(uint256):
    pass


class FeesPerGas(StableContainer[MAX_FEES_PER_GAS_FIELDS]):
    regular: Optional[FeePerGas]

    # EIP-4844
    blob: Optional[FeePerGas]


class AccessTuple(Container):
    address: ExecutionAddress
    storage_keys: List[Hash32, MAX_ACCESS_LIST_STORAGE_KEYS]


class AuthorizationPayload(StableContainer[MAX_AUTHORIZATION_PAYLOAD_FIELDS]):
    magic: Optional[TransactionType]
    chain_id: Optional[ChainId]
    address: Optional[ExecutionAddress]
    nonce: Optional[uint64]


class Authorization(Container):
    payload: AuthorizationPayload
    signature: ExecutionSignature


class TransactionPayload(StableContainer[MAX_TRANSACTION_PAYLOAD_FIELDS]):
    # EIP-2718
    type_: Optional[TransactionType]

    # EIP-155
    chain_id: Optional[ChainId]

    nonce: Optional[uint64]
    max_fees_per_gas: Optional[FeesPerGas]
    gas: Optional[uint64]
    to: Optional[ExecutionAddress]
    value: Optional[uint256]
    input_: Optional[ByteList[MAX_CALLDATA_SIZE]]

    # EIP-2930
    access_list: Optional[List[AccessTuple, MAX_ACCESS_LIST_SIZE]]

    # EIP-1559
    max_priority_fees_per_gas: Optional[FeesPerGas]

    # EIP-4844
    blob_versioned_hashes: Optional[List[VersionedHash, MAX_BLOB_COMMITMENTS_PER_BLOCK]]

    # EIP-7702
    authorization_list: Optional[List[Authorization, MAX_AUTHORIZATION_LIST_SIZE]]


class Transaction(Container):
    payload: TransactionPayload
    signature: ExecutionSignature


class BasicFeesPerGas(Profile[FeesPerGas]):
    regular: FeePerGas


class BlobFeesPerGas(Profile[FeesPerGas]):
    regular: FeePerGas
    blob: FeePerGas


class RlpLegacyTransactionPayload(Profile[TransactionPayload]):
    type_: TransactionType
    chain_id: Optional[ChainId]
    nonce: uint64
    max_fees_per_gas: BasicFeesPerGas
    gas: uint64
    to: Optional[ExecutionAddress]
    value: uint256
    input_: ByteList[MAX_CALLDATA_SIZE]


class RlpLegacyTransaction(Container):
    payload: RlpLegacyTransactionPayload
    signature: Secp256k1ExecutionSignature


def recover_rlp_tx_legacy(
    tx: RlpLegacyTransaction
) -> LegacyRlpTransaction:
    r, s, y_parity = secp256k1_unpack(tx.signature.secp256k1)
    if tx.payload.chain_id is not None:  # EIP-155
        v = U64(y_parity) + 35 + tx.payload.chain_id * 2
    else:
        v = U64(y_parity) + 27
    return LegacyRlpTransaction(
        nonce=U64(tx.payload.nonce),
        gas_price=U256(tx.payload.max_fees_per_gas.regular),
        gas=U64(tx.payload.gas),
        to=bytes(tx.payload.to if tx.payload.to is not None else []),
        value=U256(tx.payload.value),
        data=tx.payload.input_,
        v=v,
        r=r,
        s=s,
    )


class RlpAccessListTransactionPayload(Profile[TransactionPayload]):
    type_: TransactionType
    chain_id: ChainId
    nonce: uint64
    max_fees_per_gas: BasicFeesPerGas
    gas: uint64
    to: Optional[ExecutionAddress]
    value: uint256
    input_: ByteList[MAX_CALLDATA_SIZE]
    access_list: List[AccessTuple, MAX_ACCESS_LIST_SIZE]


class RlpAccessListTransaction(Container):
    payload: RlpAccessListTransactionPayload
    signature: Secp256k1ExecutionSignature


def recover_rlp_tx_2930(
    tx: RlpAccessListTransaction
) -> AccessListRlpTransaction:
    r, s, y_parity = secp256k1_unpack(tx.signature.secp256k1)
    return AccessListRlpTransaction(
        chain_id=U256(tx.payload.chain_id),
        nonce=U64(tx.payload.nonce),
        gas_price=U256(tx.payload.max_fees_per_gas.regular),
        gas=U64(tx.payload.gas),
        to=bytes(tx.payload.to if tx.payload.to is not None else []),
        value=U256(tx.payload.value),
        data=tx.payload.input_,
        access_list=tuple([(
            Address(access_tuple.address),
            tuple(access_tuple.storage_keys),
        ) for access_tuple in tx.payload.access_list]),
        y_parity=U256(y_parity),
        r=r,
        s=s,
    )


class RlpFeeMarketTransactionPayload(Profile[TransactionPayload]):
    type_: TransactionType
    chain_id: ChainId
    nonce: uint64
    max_fees_per_gas: BasicFeesPerGas
    gas: uint64
    to: Optional[ExecutionAddress]
    value: uint256
    input_: ByteList[MAX_CALLDATA_SIZE]
    access_list: List[AccessTuple, MAX_ACCESS_LIST_SIZE]
    max_priority_fees_per_gas: BasicFeesPerGas


class RlpFeeMarketTransaction(Container):
    payload: RlpFeeMarketTransactionPayload
    signature: Secp256k1ExecutionSignature


def recover_rlp_tx_1559(
    tx: RlpFeeMarketTransaction
) -> FeeMarketRlpTransaction:
    r, s, y_parity = secp256k1_unpack(tx.signature.secp256k1)
    return FeeMarketRlpTransaction(
        chain_id=U256(tx.payload.chain_id),
        nonce=U64(tx.payload.nonce),
        max_priority_fee_per_gas=U256(tx.payload.max_priority_fees_per_gas.regular),
        max_fee_per_gas=U256(tx.payload.max_fees_per_gas.regular),
        gas=U64(tx.payload.gas),
        to=bytes(tx.payload.to if tx.payload.to is not None else []),
        value=U256(tx.payload.value),
        data=tx.payload.input_,
        access_list=tuple([(
            Address(access_tuple.address),
            tuple(access_tuple.storage_keys),
        ) for access_tuple in tx.payload.access_list]),
        y_parity=U256(y_parity),
        r=r,
        s=s,
    )


class RlpBlobTransactionPayload(Profile[TransactionPayload]):
    type_: TransactionType
    chain_id: ChainId
    nonce: uint64
    max_fees_per_gas: BlobFeesPerGas
    gas: uint64
    to: ExecutionAddress
    value: uint256
    input_: ByteList[MAX_CALLDATA_SIZE]
    access_list: List[AccessTuple, MAX_ACCESS_LIST_SIZE]
    max_priority_fees_per_gas: BlobFeesPerGas
    blob_versioned_hashes: List[VersionedHash, MAX_BLOB_COMMITMENTS_PER_BLOCK]


class RlpBlobTransaction(Container):
    payload: RlpBlobTransactionPayload
    signature: Secp256k1ExecutionSignature


def recover_rlp_tx_4844(
    tx: RlpBlobTransaction
) -> BlobRlpTransaction:
    r, s, y_parity = secp256k1_unpack(tx.signature.secp256k1)
    return BlobRlpTransaction(
        chain_id=U256(tx.payload.chain_id),
        nonce=U64(tx.payload.nonce),
        max_priority_fee_per_gas=U256(tx.payload.max_priority_fees_per_gas.regular),
        max_fee_per_gas=U256(tx.payload.max_fees_per_gas.regular),
        gas=U64(tx.payload.gas),
        to=tx.payload.to,
        value=U256(tx.payload.value),
        data=tx.payload.input_,
        access_list=tuple([(
            Address(access_tuple.address),
            tuple(access_tuple.storage_keys),
        ) for access_tuple in tx.payload.access_list]),
        max_fee_per_blob_gas=U256(tx.payload.max_fees_per_gas.blob),
        blob_versioned_hashes=tuple(tx.payload.blob_versioned_hashes),
        y_parity=U256(y_parity),
        r=r,
        s=s,
    )


class RlpSetCodeAuthorizationPayload(Profile[AuthorizationPayload]):
    magic: TransactionType
    chain_id: Optional[ChainId]
    address: ExecutionAddress
    nonce: uint64


class RlpSetCodeAuthorization(Container):
    payload: RlpSetCodeAuthorizationPayload
    signature: Secp256k1ExecutionSignature


class RlpSetCodeTransactionPayload(Profile[TransactionPayload]):
    type_: TransactionType
    chain_id: ChainId
    nonce: uint64
    max_fees_per_gas: BasicFeesPerGas
    gas: uint64
    to: ExecutionAddress
    value: uint256
    input_: ByteList[MAX_CALLDATA_SIZE]
    access_list: List[AccessTuple, MAX_ACCESS_LIST_SIZE]
    max_priority_fees_per_gas: BasicFeesPerGas
    authorization_list: List[Authorization, MAX_AUTHORIZATION_LIST_SIZE]


class RlpSetCodeTransaction(Container):
    payload: RlpSetCodeTransactionPayload
    signature: Secp256k1ExecutionSignature


def recover_rlp_auth_7702(
    auth: RlpSetCodeAuthorization
) -> SetCodeRlpAuthorization:
    r, s, y_parity = secp256k1_unpack(auth.signature.secp256k1)
    return SetCodeRlpAuthorization(
        chain_id=U64(auth.payload.chain_id if auth.payload.chain_id is not None else 0),
        address=auth.payload.address,
        nonce=U64(auth.payload.nonce),
        y_parity=U256(y_parity),
        r=r,
        s=s,
    )


def recover_rlp_tx_7702(
    tx: RlpSetCodeTransaction
) -> SetCodeRlpTransaction:
    r, s, y_parity = secp256k1_unpack(tx.signature.secp256k1)
    return SetCodeRlpTransaction(
        chain_id=U256(tx.payload.chain_id),
        nonce=U64(tx.payload.nonce),
        max_priority_fee_per_gas=U256(tx.payload.max_priority_fees_per_gas.regular),
        max_fee_per_gas=U256(tx.payload.max_fees_per_gas.regular),
        gas=U64(tx.payload.gas),
        to=tx.payload.to,
        value=U256(tx.payload.value),
        data=tx.payload.input_,
        access_list=tuple([(
            Address(access_tuple.address),
            tuple(access_tuple.storage_keys),
        ) for access_tuple in tx.payload.access_list]),
        authorizations=tuple([
            recover_rlp_auth_7702(auth)
            for auth in tx.payload.authorization_list
        ]),
        y_parity=U256(y_parity),
        r=r,
        s=s,
    )


AnyRlpConvertedTransaction = Union[
    RlpLegacyTransaction,
    RlpAccessListTransaction,
    RlpFeeMarketTransaction,
    RlpBlobTransaction,
    RlpSetCodeTransaction,
]


def recover_rlp_tx(tx: AnyRlpConvertedTransaction) -> AnyRlpTransaction:
    if isinstance(tx, RlpLegacyTransaction):
        return recover_rlp_tx_legacy(tx)
    elif isinstance(tx, RlpAccessListTransaction):
        return recover_rlp_tx_2930(tx)
    elif isinstance(tx, RlpFeeMarketTransaction):
        return recover_rlp_tx_1559(tx)
    elif isinstance(tx, RlpBlobTransaction):
        return recover_rlp_tx_4844(tx)
    elif isinstance(tx, RlpSetCodeTransaction):
        return recover_rlp_tx_7702(tx)


LEGACY_TX_TYPE = TransactionType(0x00)
ACCESS_LIST_TX_TYPE = TransactionType(0x01)
FEE_MARKET_TX_TYPE = TransactionType(0x02)
BLOB_TX_TYPE = TransactionType(0x03)
SET_CODE_TX_TYPE = TransactionType(0x04)
SET_CODE_TX_MAGIC = TransactionType(0x05)
SSZ_TX_TYPE = TransactionType(0x1f)


def identify_authorization_profile(auth: Authorization) -> Type[Profile]:
    if auth.payload.magic == SET_CODE_TX_MAGIC:
        if auth.payload.chain_id == 0:
            raise InvalidBlock
        return RlpSetCodeAuthorization

    raise InvalidBlock


def identify_transaction_profile(tx: Transaction) -> Type[Profile]:
    if tx.payload.type_ == SET_CODE_TX_TYPE:
        for auth in tx.payload.authorization_list or []:
            auth = identify_authorization_profile(auth)(backing=auth.get_backing())
            if not isinstance(auth, RlpSetCodeAuthorization):
                raise InvalidBlock
        return RlpSetCodeTransaction

    if tx.payload.type_ == BLOB_TX_TYPE:
        if (tx.payload.max_priority_fees_per_gas or FeesPerGas()).blob != 0:
            raise InvalidBlock
        return RlpBlobTransaction

    if tx.payload.type_ == FEE_MARKET_TX_TYPE:
        return RlpFeeMarketTransaction

    if tx.payload.type_ == ACCESS_LIST_TX_TYPE:
        return RlpAccessListTransaction

    if tx.payload.type_ == LEGACY_TX_TYPE:
        return RlpLegacyTransaction

    raise InvalidBlock


AnyTransaction = Union[
    AnyRlpConvertedTransaction,
]


AnyRlpConvertedAuthorization = Union[
    RlpSetCodeAuthorization,
]


def recover_rlp_auth(authorization: AnyRlpConvertedAuthorization) -> AnyRlpAuthorization:
    if isinstance(authorization, RlpSetCodeAuthorization):
        return recover_rlp_auth_7702(authorization)


def identify_authorization_profile(authorization: Authorization) -> Type[Profile]:
    if authorization.payload.magic == SET_CODE_TX_MAGIC:
        return RlpSetCodeAuthorization

    raise InvalidBlock


AnyAuthorization = Union[
    AnyRlpConvertedAuthorization
]


def encode_transaction(tx: AnyTransaction) -> Bytes:
    """
    Encode a transaction. Needed because non-legacy transactions aren't RLP.
    """
    stable_tx = Transaction(backing=tx.get_backing())
    data = snappy.StreamCompressor().add_chunk(stable_tx.encode_bytes())
    return bytes([SSZ_TX_TYPE]) + data


def decode_transaction(tx: Bytes) -> AnyTransaction:
    """
    Decode a transaction. Needed because non-legacy transactions aren't RLP.
    """
    if len(tx) < 1 or tx[0] != SSZ_TX_TYPE:
        raise InvalidBlock
    data = snappy.StreamDecompressor().decompress(tx[1:])
    try:
        stable_tx = Transaction.decode_bytes(data)
    except ValueError as e:
        raise InvalidBlock from e
    return identify_transaction_profile(stable_tx)(backing=stable_tx.get_backing())


def recover_signer(
    signature: ByteVector[SECP256K1_SIGNATURE_SIZE],
    sig_hash: Hash32,
) -> Address:
    secp256k1_validate(signature)
    public_key = secp256k1_recover_packed(signature, sig_hash)
    return Address(keccak256(public_key)[12:32])


def upgrade_rlp_tx_legacy(
    tx: LegacyRlpTransaction
) -> RlpLegacyTransaction:
    if tx.v == 0:
        chain_id = None
        y_parity = 0
    else:
        try:
            chain_id = ((U64(tx.v) - 35) >> 1) if tx.v not in (27, 28) else None
        except OverflowError as e:
            raise InvalidBlock from e
        y_parity = ((tx.v & 0x1) == 0)
    return RlpLegacyTransaction(
        payload=RlpLegacyTransactionPayload(
            type_=LEGACY_TX_TYPE,
            chain_id=chain_id,
            nonce=tx.nonce,
            max_fees_per_gas=BasicFeesPerGas(
                regular=tx.gas_price,
            ),
            gas=tx.gas,
            to=ExecutionAddress(tx.to) if len(tx.to) > 0 else None,
            value=tx.value,
            input_=tx.data,
        ),
        signature=Secp256k1ExecutionSignature(
            secp256k1=secp256k1_pack(tx.r, tx.s, y_parity),
        ),
    )


def upgrade_rlp_tx_2930(
    tx: AccessListRlpTransaction
) -> RlpAccessListTransaction:
    return RlpAccessListTransaction(
        payload=RlpAccessListTransactionPayload(
            type_=ACCESS_LIST_TX_TYPE,
            chain_id=tx.chain_id,
            nonce=tx.nonce,
            max_fees_per_gas=BasicFeesPerGas(
                regular=tx.gas_price,
            ),
            gas=tx.gas,
            to=ExecutionAddress(tx.to) if len(tx.to) > 0 else None,
            value=tx.value,
            input_=tx.data,
            access_list=[AccessTuple(
                address=address,
                storage_keys=keys,
            ) for address, keys in tx.access_list],
        ),
        signature=Secp256k1ExecutionSignature(
            secp256k1=secp256k1_pack(tx.r, tx.s, tx.y_parity),
        ),
    )


def upgrade_rlp_tx_1559(
    tx: FeeMarketRlpTransaction
) -> RlpFeeMarketTransaction:
    return RlpFeeMarketTransaction(
        payload=RlpFeeMarketTransactionPayload(
            type_=FEE_MARKET_TX_TYPE,
            chain_id=tx.chain_id,
            nonce=tx.nonce,
            max_fees_per_gas=BasicFeesPerGas(
                regular=tx.max_fee_per_gas,
            ),
            gas=tx.gas,
            to=ExecutionAddress(tx.to) if len(tx.to) > 0 else None,
            value=tx.value,
            input_=tx.data,
            access_list=[AccessTuple(
                address=address,
                storage_keys=keys,
            ) for address, keys in tx.access_list],
            max_priority_fees_per_gas=BasicFeesPerGas(
                regular=tx.max_priority_fee_per_gas,
            ),
        ),
        signature=Secp256k1ExecutionSignature(
            secp256k1=secp256k1_pack(tx.r, tx.s, tx.y_parity),
        ),
    )


def upgrade_rlp_tx_4844(
    tx: BlobRlpTransaction
) -> RlpBlobTransaction:
    return RlpBlobTransaction(
        payload=RlpBlobTransactionPayload(
            type_=BLOB_TX_TYPE,
            chain_id=tx.chain_id,
            nonce=tx.nonce,
            max_fees_per_gas=BlobFeesPerGas(
                regular=tx.max_fee_per_gas,
                blob=tx.max_fee_per_blob_gas,
            ),
            gas=tx.gas,
            to=ExecutionAddress(tx.to),
            value=tx.value,
            input_=tx.data,
            access_list=[AccessTuple(
                address=address,
                storage_keys=keys,
            ) for address, keys in tx.access_list],
            max_priority_fees_per_gas=BlobFeesPerGas(
                regular=tx.max_priority_fee_per_gas,
                blob=FeePerGas(0),
            ),
            blob_versioned_hashes=tx.blob_versioned_hashes,
        ),
        signature=Secp256k1ExecutionSignature(
            secp256k1=secp256k1_pack(tx.r, tx.s, tx.y_parity),
        ),
    )


def upgrade_rlp_tx_7702(
    tx: SetCodeRlpTransaction
) -> RlpSetCodeTransaction:
    return RlpSetCodeTransaction(
        payload=RlpSetCodeTransactionPayload(
            type_=SET_CODE_TX_TYPE,
            chain_id=tx.chain_id,
            nonce=tx.nonce,
            max_fees_per_gas=BasicFeesPerGas(
                regular=tx.max_fee_per_gas,
            ),
            gas=tx.gas,
            to=ExecutionAddress(tx.to),
            value=tx.value,
            input_=tx.data,
            access_list=[AccessTuple(
                address=address,
                storage_keys=keys,
            ) for address, keys in tx.access_list],
            max_priority_fees_per_gas=BasicFeesPerGas(
                regular=tx.max_priority_fee_per_gas,
            ),
            authorization_list=[Authorization(backing=RlpSetCodeAuthorization(
                payload=RlpSetCodeAuthorizationPayload(
                    magic=SET_CODE_TX_MAGIC,
                    chain_id=auth.chain_id if auth.chain_id != 0 else None,
                    address=ExecutionAddress(auth.address),
                    nonce=auth.nonce,
                ),
                signature=Secp256k1ExecutionSignature(
                    secp256k1=secp256k1_pack(auth.r, auth.s, auth.y_parity),
                ),
            ).get_backing()) for auth in tx.authorizations],
        ),
        signature=Secp256k1ExecutionSignature(
            secp256k1=secp256k1_pack(tx.r, tx.s, tx.y_parity),
        ),
    )


def upgrade_rlp_tx(tx: AnyRlpTransaction) -> AnyTransaction:
    if isinstance(tx, LegacyRlpTransaction):
        return upgrade_rlp_tx_legacy(tx)
    elif isinstance(tx, AccessListRlpTransaction):
        return upgrade_rlp_tx_2930(tx)
    elif isinstance(tx, FeeMarketRlpTransaction):
        return upgrade_rlp_tx_1559(tx)
    elif isinstance(tx, BlobRlpTransaction):
        return upgrade_rlp_tx_4844(tx)
    elif isinstance(tx, SetCodeRlpTransaction):
        return upgrade_rlp_tx_7702(tx)


def decode_network_transaction(tx: Bytes) -> AnyTransaction:
    if len(tx) < 1:
        raise InvalidBlock
    elif tx[0] == 1:
        return upgrade_rlp_tx_2930(rlp.decode_to(AccessListRlpTransaction, tx[1:]))
    elif tx[0] == 2:
        return upgrade_rlp_tx_1559(rlp.decode_to(FeeMarketRlpTransaction, tx[1:]))
    elif tx[0] == 3:
        return upgrade_rlp_tx_4844(rlp.decode_to(BlobRlpTransaction, tx[1:]))
    elif tx[0] == 4:
        return upgrade_rlp_tx_7702(rlp.decode_to(SetCodeRlpTransaction, tx[1:]))
    elif 0xc0 <= tx[0] <= 0xfe:
        return upgrade_rlp_tx_legacy(rlp.decode_to(LegacyRlpTransaction, tx))
    else:
        raise InvalidBlock
