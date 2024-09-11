"""
RLP transaction formats that are converted to SSZ when included in blocks.
"""
from dataclasses import dataclass
from typing import Tuple, Union

from ethereum.crypto.hash import Hash32, keccak256

from .. import rlp
from ..base_types import (
    U64,
    U256,
    Bytes,
    Bytes0,
    Bytes32,
    Uint,
    slotted_freezable,
)
from .fork_types import Address, VersionedHash


@slotted_freezable
@dataclass
class LegacyRlpTransaction:
    """
    Atomic operation performed on the block chain.
    """

    nonce: U256
    gas_price: Uint
    gas: Uint
    to: Union[Bytes0, Address]
    value: U256
    data: Bytes
    v: U256
    r: U256
    s: U256


def signing_hash_pre155(tx: LegacyRlpTransaction) -> Hash32:
    """
    Compute the hash of a transaction used in a legacy (pre EIP 155) signature.

    Parameters
    ----------
    tx :
        Transaction of interest.

    Returns
    -------
    hash : `ethereum.crypto.hash.Hash32`
        Hash of the transaction.
    """
    return keccak256(
        rlp.encode(
            (
                tx.nonce,
                tx.gas_price,
                tx.gas,
                tx.to,
                tx.value,
                tx.data,
            )
        )
    )


def signing_hash_155(tx: LegacyRlpTransaction, chain_id: U64) -> Hash32:
    """
    Compute the hash of a transaction used in a EIP 155 signature.

    Parameters
    ----------
    tx :
        Transaction of interest.
    chain_id :
        The id of the current chain.

    Returns
    -------
    hash : `ethereum.crypto.hash.Hash32`
        Hash of the transaction.
    """
    return keccak256(
        rlp.encode(
            (
                tx.nonce,
                tx.gas_price,
                tx.gas,
                tx.to,
                tx.value,
                tx.data,
                chain_id,
                Uint(0),
                Uint(0),
            )
        )
    )


@slotted_freezable
@dataclass
class AccessListRlpTransaction:
    """
    The transaction type added in EIP-2930 to support access lists.
    """

    chain_id: U64
    nonce: U256
    gas_price: Uint
    gas: Uint
    to: Union[Bytes0, Address]
    value: U256
    data: Bytes
    access_list: Tuple[Tuple[Address, Tuple[Bytes32, ...]], ...]
    y_parity: U256
    r: U256
    s: U256


def signing_hash_2930(tx: AccessListRlpTransaction) -> Hash32:
    """
    Compute the hash of a transaction used in a EIP 2930 signature.

    Parameters
    ----------
    tx :
        Transaction of interest.

    Returns
    -------
    hash : `ethereum.crypto.hash.Hash32`
        Hash of the transaction.
    """
    return keccak256(
        b"\x01"
        + rlp.encode(
            (
                tx.chain_id,
                tx.nonce,
                tx.gas_price,
                tx.gas,
                tx.to,
                tx.value,
                tx.data,
                tx.access_list,
            )
        )
    )


@slotted_freezable
@dataclass
class FeeMarketRlpTransaction:
    """
    The transaction type added in EIP-1559.
    """

    chain_id: U64
    nonce: U256
    max_priority_fee_per_gas: Uint
    max_fee_per_gas: Uint
    gas: Uint
    to: Union[Bytes0, Address]
    value: U256
    data: Bytes
    access_list: Tuple[Tuple[Address, Tuple[Bytes32, ...]], ...]
    y_parity: U256
    r: U256
    s: U256


def signing_hash_1559(tx: FeeMarketRlpTransaction) -> Hash32:
    """
    Compute the hash of a transaction used in a EIP 1559 signature.

    Parameters
    ----------
    tx :
        Transaction of interest.

    Returns
    -------
    hash : `ethereum.crypto.hash.Hash32`
        Hash of the transaction.
    """
    return keccak256(
        b"\x02"
        + rlp.encode(
            (
                tx.chain_id,
                tx.nonce,
                tx.max_priority_fee_per_gas,
                tx.max_fee_per_gas,
                tx.gas,
                tx.to,
                tx.value,
                tx.data,
                tx.access_list,
            )
        )
    )


@slotted_freezable
@dataclass
class BlobRlpTransaction:
    """
    The transaction type added in EIP-4844.
    """

    chain_id: U64
    nonce: U256
    max_priority_fee_per_gas: Uint
    max_fee_per_gas: Uint
    gas: Uint
    to: Address
    value: U256
    data: Bytes
    access_list: Tuple[Tuple[Address, Tuple[Bytes32, ...]], ...]
    max_fee_per_blob_gas: U256
    blob_versioned_hashes: Tuple[VersionedHash, ...]
    y_parity: U256
    r: U256
    s: U256


def signing_hash_4844(tx: BlobRlpTransaction) -> Hash32:
    """
    Compute the hash of a transaction used in a EIP-4844 signature.

    Parameters
    ----------
    tx :
        Transaction of interest.

    Returns
    -------
    hash : `ethereum.crypto.hash.Hash32`
        Hash of the transaction.
    """
    return keccak256(
        b"\x03"
        + rlp.encode(
            (
                tx.chain_id,
                tx.nonce,
                tx.max_priority_fee_per_gas,
                tx.max_fee_per_gas,
                tx.gas,
                tx.to,
                tx.value,
                tx.data,
                tx.access_list,
                tx.max_fee_per_blob_gas,
                tx.blob_versioned_hashes,
            )
        )
    )


AnyRlpTransaction = Union[
    LegacyRlpTransaction,
    AccessListRlpTransaction,
    FeeMarketRlpTransaction,
    BlobRlpTransaction,
]


def signing_hash_rlp(tx: AnyRlpTransaction) -> Hash32:
    if isinstance(tx, LegacyRlpTransaction):
        if (tx.v not in (27, 28)):  # EIP-155
            chain_id = ((U256(tx.v) - 35) >> 1)
            return signing_hash_155(tx, chain_id)
        else:
            return signing_hash_pre155(tx)
    elif isinstance(tx, AccessListRlpTransaction):
        return signing_hash_2930(tx)
    elif isinstance(tx, FeeMarketRlpTransaction):
        return signing_hash_1559(tx)
    elif isinstance(tx, BlobRlpTransaction):
        return signing_hash_4844(tx)


def tx_hash_rlp(tx: AnyRlpTransaction) -> Hash32:
    if isinstance(tx, LegacyRlpTransaction):
        return keccak256(rlp.encode(tx))
    elif isinstance(tx, AccessListRlpTransaction):
        return keccak256(b"\x01" + rlp.encode(tx))
    elif isinstance(tx, FeeMarketRlpTransaction):
        return keccak256(b"\x02" + rlp.encode(tx))
    elif isinstance(tx, BlobRlpTransaction):
        return keccak256(b"\x03" + rlp.encode(tx))
