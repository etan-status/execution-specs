"""
Set EOA account code.
"""


from typing import Tuple

from ethereum.base_types import U64, U256, Bytes, Uint
from ethereum.crypto import InvalidSignature
from ethereum.crypto.elliptic_curve import SECP256K1N, secp256k1_recover
from ethereum.crypto.hash import Hash32, keccak256
from ethereum.exceptions import InvalidBlock

from ..fork_types import Address
from ..state import account_exists, get_account, increment_nonce, set_code
from ..transactions import (
    AnyAuthorization,
    AnyRlpConvertedAuthorization,
    identify_authorization_profile,
    recover_rlp_auth,
    recover_signer,
)
from ..transactions_rlp import auth_hash_rlp
from ..vm.gas import GAS_COLD_ACCOUNT_ACCESS, GAS_WARM_ACCESS
from . import Environment, Evm, Message

EOA_DELEGATION_MARKER = b"\xEF\x01\x00"
EOA_DELEGATION_MARKER_LENGTH = len(EOA_DELEGATION_MARKER)
EOA_DELEGATED_CODE_LENGTH = 23
PER_EMPTY_ACCOUNT_COST = 25000
PER_AUTH_BASE_COST = 2500


def is_valid_delegation(code: bytes) -> bool:
    """
    Whether the code is a valid delegation designation.

    Parameters
    ----------
    code: `bytes`
        The code to check.

    Returns
    -------
    valid : `bool`
        True if the code is a valid delegation designation,
        False otherwise.
    """
    if (
        len(code) == EOA_DELEGATED_CODE_LENGTH
        and code[:EOA_DELEGATION_MARKER_LENGTH] == EOA_DELEGATION_MARKER
    ):
        return True
    return False


def auth_hash(auth: AnyAuthorization) -> Hash32:
    if isinstance(auth, AnyRlpConvertedAuthorization):
        auth = recover_rlp_auth(auth)
        return auth_hash_rlp(auth)


def recover_authority(authorization: AnyAuthorization) -> Address:
    """
    Recover the authority address from the authorization.

    Parameters
    ----------
    authorization
        The authorization to recover the authority from.

    Raises
    ------
    InvalidSignature
        If the signature is invalid.

    Returns
    -------
    authority : `Address`
        The recovered authority address.
    """
    return recover_signer(
        authorization.signature.secp256k1, auth_hash(authorization))


def access_delegation(
    evm: Evm, address: Address
) -> Tuple[bool, Address, Bytes, Uint]:
    """
    Get the delegation address, code, and the cost of access from the address.

    Parameters
    ----------
    evm : `Evm`
        The execution frame.
    address : `Address`
        The address to get the delegation from.

    Returns
    -------
    delegation : `Tuple[bool, Address, Bytes, Uint]`
        The delegation address, code, and access gas cost.
    """
    code = get_account(evm.env.state, address).code
    if not is_valid_delegation(code):
        return False, address, code, Uint(0)

    address = Address(code[EOA_DELEGATION_MARKER_LENGTH:])
    if address in evm.accessed_addresses:
        access_gas_cost = GAS_WARM_ACCESS
    else:
        evm.accessed_addresses.add(address)
        access_gas_cost = GAS_COLD_ACCOUNT_ACCESS
    code = get_account(evm.env.state, address).code

    return True, address, code, access_gas_cost


def set_delegation(message: Message, env: Environment) -> U256:
    """
    Set the delegation code for the authorities in the message.

    Parameters
    ----------
    message :
        Transaction specific items.
    env :
        External items required for EVM execution.

    Returns
    -------
    refund_counter: `U256`
        Refund from authority which already exists in state.
    """
    refund_counter = U256(0)
    for auth in message.authorizations:
        auth = identify_authorization_profile(auth)(backing=auth.get_backing())

        if auth.payload.chain_id not in (env.chain_id, None):
            continue

        try:
            authority = recover_authority(auth)
        except InvalidSignature:
            continue

        message.accessed_addresses.add(authority)

        authority_account = get_account(env.state, authority)
        authority_code = authority_account.code

        if authority_code != bytearray() and not is_valid_delegation(
            authority_code
        ):
            continue

        authority_nonce = authority_account.nonce
        if authority_nonce != auth.payload.nonce:
            continue

        if account_exists(env.state, authority):
            refund_counter += PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST

        code_to_set = EOA_DELEGATION_MARKER + auth.payload.address
        set_code(env.state, authority, code_to_set)

        increment_nonce(env.state, authority)

    if message.code_address is None:
        raise InvalidBlock("Invalid type 4 transaction: no target")
    message.code = get_account(env.state, message.code_address).code

    if is_valid_delegation(message.code):
        message.code_address = Address(
            message.code[EOA_DELEGATION_MARKER_LENGTH:]
        )
        message.accessed_addresses.add(message.code_address)

        message.code = get_account(env.state, message.code_address).code

    return refund_counter
