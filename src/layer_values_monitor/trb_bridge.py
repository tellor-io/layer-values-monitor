"""Trusted value for TRBBridge query type."""

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast

from layer_values_monitor.evm_connections import get_web3_connection, invalidate_web3_connection

from eth_abi.abi import encode as abi_encode
from telliot_core.apps.telliot_config import TelliotConfig
from web3 import Web3
from web3.contract import Contract

if TYPE_CHECKING:
    from web3.types import BlockIdentifier

ZERO_ADDRESS = "0x" + "0" * 40

# Contract ABI for deposits mapping
# Based on: mapping(uint256 depositId => DepositDetails) public deposits;
# where DepositDetails(address sender, string layerRecipient, uint256 amount, uint256 tip, uint256 blockNumber)
DEPOSITS_ABI = [
    {
        "inputs": [{"name": "depositId", "type": "uint256"}],
        "name": "deposits",
        "outputs": [
            {"name": "sender", "type": "address"},
            {"name": "layerRecipient", "type": "string"},
            {"name": "amount", "type": "uint256"},
            {"name": "tip", "type": "uint256"},
            {"name": "blockNumber", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    }
]

# Contract ABI for the gapless deposit counter: `uint256 public depositId`.
# Reverted deposits revert the increment too, and deposits(id) structs are written once
# and never deleted, so every deposit ever made is permanently enumerable from state.
DEPOSIT_ID_ABI = [
    {
        "inputs": [],
        "name": "depositId",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]


def read_deposit_counter(w3: Web3, contract_address: str) -> int:
    """Read the contract's `depositId()` counter (next deposit ID == current count).

    Raises on RPC failure — the caller decides whether a missing counter is retryable.
    """
    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=DEPOSIT_ID_ABI)
    return int(contract.functions.depositId().call())


def trusted_dict(deposit: tuple) -> dict:
    """Render a fetch_deposit tuple as the dict shape stored in reported_json."""
    return {
        "eth_address": deposit[0],
        "layer_address": deposit[1],
        "amount": deposit[2],
        "tip": deposit[3],
    }


def is_zero_struct(deposit_details: tuple) -> bool:
    """Detect the all-zeros default of deposits(depositId) (not yet visible / nonexistent).

    A lagging node answers a real deposit with this struct, so it must NEVER be treated
    as a trusted value — it would "mismatch" a valid report.
    """
    sender, layer_recipient, amount, tip, block_number = deposit_details
    return str(sender).lower() == ZERO_ADDRESS and layer_recipient == "" and amount == 0 and tip == 0 and block_number == 0


def deposit_query_id(deposit_id: int, query_string: str = "TRBBridgeV2") -> str:
    """QueryId for a bridge deposit: keccak(abi.encode(typeString, abi.encode(toLayer, depositId)))."""
    query_data = abi_encode(
        ["string", "bytes"],
        [query_string, abi_encode(["bool", "uint256"], [True, deposit_id])],
    )
    return "0x" + Web3.keccak(query_data).hex()


def decode_query_data(query_data: str) -> int | None:
    """Decode TRBBridge queryData to extract deposit ID.

    Based on the example queryData with descriptors:
    {"type":"TRBBridge","arg1":"true","arg2":"1"}

    Args:
        query_data: Hex string of the query data

    Returns:
        Deposit ID as integer, or None if decoding fails

    """
    try:
        # Remove 0x prefix if present
        if query_data.startswith("0x"):
            query_data = query_data[2:]

        # Convert hex to bytes
        data_bytes = bytes.fromhex(query_data)

        # Based on the provided example, the queryData structure contains:
        # - Query type string "TRBBridge"
        # - Parameters including arg1="true" and arg2="1" (deposit ID)

        # The example shows arg2="1" which should be the deposit ID
        # From the hex data, we need to extract the deposit ID parameter
        # Looking at the pattern, the last 32 bytes should contain the deposit ID

        # Extract deposit ID from the last 32-byte word
        deposit_id = int.from_bytes(data_bytes[-32:], byteorder="big")

        return deposit_id
    except Exception as e:
        logging.error(f"Failed to decode TRBBridge queryData: {e}")
        return None


def decode_report_value(value_hex: str) -> tuple[str, str, int, int] | None:
    """Decode TRBBridge report value to extract deposit details.

    Based on the example value from encodeReport function:
    encodeReport(address _ethAddress, string calldata _layerAddress, uint256 _amount, uint256 _tip)

    Example:
    - _ethAddress: 0xAE7CFe4CF579Ec060f95d951bD5260A5A8c0dcDC
    - _layerAddress: "tellor168hv5trkskdwvxj2hzqdmch7r7l0prlnepslrz"
    - _amount: 1000000000000000000 (1 ETH in wei)
    - _tip: 100000000

    Args:
        value_hex: Hex string of the reported value

    Returns:
        Tuple of (eth_address, layer_address, amount, tip) or None if decoding fails

    """
    try:
        # Remove 0x prefix if present
        if value_hex.startswith("0x"):
            value_hex = value_hex[2:]

        # Convert hex to bytes
        value_bytes = bytes.fromhex(value_hex)

        # ABI decode the report value: (address, string, uint256, uint256)
        # Structure: address (32 bytes), string offset (32 bytes), amount (32 bytes), tip (32 bytes), string data

        # Extract address (bytes 0-32, but address is in the last 20 bytes)
        eth_address = "0x" + value_bytes[12:32].hex()

        # Extract string offset (bytes 32-64)
        string_offset = int.from_bytes(value_bytes[32:64], byteorder="big")

        # Extract amount (bytes 64-96)
        amount = int.from_bytes(value_bytes[64:96], byteorder="big")

        # Extract tip (bytes 96-128)
        tip = int.from_bytes(value_bytes[96:128], byteorder="big")

        # Extract layer address string
        # Get string length from the offset position
        string_length = int.from_bytes(value_bytes[string_offset : string_offset + 32], byteorder="big")
        # Get string data
        layer_address = value_bytes[string_offset + 32 : string_offset + 32 + string_length].decode("utf-8").rstrip("\x00")

        return eth_address.lower(), layer_address, amount, tip
    except Exception as e:
        logging.error(f"Failed to decode TRBBridge report value: {e}")
        return None


async def fetch_deposit(
    provider_builder: Callable[[int], Web3 | None],
    contract_address: str,
    deposit_id: int,
    *,
    anchor: str | None = None,
    sanity: bool = True,
    max_attempts: int = 3,
    backoff_s: tuple[float, ...] = (2.0, 6.0),
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    logger: Any = None,
) -> tuple[tuple | None, str]:
    """Hardened deposits(depositId) read: retries, provider rotation, anchor fallback, sanity check.

    Args:
        provider_builder: callable(attempt: int) -> Web3 | None. Called once per attempt so the
            caller can fail over to a different provider on retries.
        contract_address: TRBBridge contract address.
        deposit_id: deposit ID from the query data.
        anchor: block_identifier for the read (e.g. "finalized"). Providers that reject the
            anchor get exactly one automatic un-anchored retry before the attempt counts as failed.
        sanity: when True, an all-zeros struct returns error_kind "zero_struct" instead of
            being handed back as if it were a real record.
        max_attempts: number of provider attempts before giving up.
        backoff_s: delays applied *between* attempts (not after the last one).
        sleep: injectable awaitable sleep (tests pass an instant one).
        logger: logger instance.

    Returns:
        (deposit, error_kind) with deposit = (sender, layer_recipient, amount, tip) on success
        (None otherwise) and error_kind in {"ok", "zero_struct", "rpc_error"}. A missing
        deposit reads as the zero struct, so it surfaces as "zero_struct", not a separate kind.

    """
    if logger is None:
        logger = logging.getLogger(__name__)

    last_error: str | None = None
    for attempt in range(max_attempts):
        if attempt > 0:
            await sleep(backoff_s[min(attempt - 1, len(backoff_s) - 1)])

        try:
            w3 = provider_builder(attempt)
        except Exception as e:
            last_error = f"provider build failed: {e}"
            logger.warning(f"deposit {deposit_id} attempt {attempt + 1}: {last_error}")
            continue
        if w3 is None:
            last_error = "no RPC provider available"
            logger.warning(f"deposit {deposit_id} attempt {attempt + 1}: {last_error}")
            continue

        try:
            contract: Contract = w3.eth.contract(
                address=Web3.to_checksum_address(contract_address), abi=DEPOSITS_ABI
            )
            fn = contract.functions.deposits(deposit_id)
            try:
                if anchor is not None:
                    try:
                        deposit_details = fn.call(block_identifier=cast("BlockIdentifier", anchor))
                    except Exception as anchor_err:
                        # Non-archive providers reject some block tags: one un-anchored retry.
                        logger.warning(
                            f"deposits({deposit_id}) rejected anchor '{anchor}' ({anchor_err}); retrying un-anchored"
                        )
                        deposit_details = fn.call()
                else:
                    deposit_details = fn.call()
            except Exception as call_err:
                last_error = f"deposits() call failed: {call_err}"
                logger.warning(f"deposit {deposit_id} attempt {attempt + 1}: {last_error}")
                continue

            sender, layer_recipient, amount, tip, block_number = deposit_details

            if sanity and is_zero_struct(deposit_details):
                # Not a trusted value: either lagging node or deposit doesn't exist.
                logger.warning(f"deposit {deposit_id}: zero-struct return, not treated as trusted value")
                return None, "zero_struct"

            logger.info(
                f"Retrieved deposit {deposit_id} - Sender: {sender}, Layer_Addr: {layer_recipient}, "
                f"Amount: {amount}, Tip: {tip}, Block Number: {block_number}"
            )
            return (str(sender).lower(), layer_recipient, int(amount), int(tip)), "ok"

        except Exception as e:
            last_error = f"unexpected error: {e}"
            logger.warning(f"deposit {deposit_id} attempt {attempt + 1}: {last_error}")
            continue

    logger.error(f"deposit {deposit_id}: all {max_attempts} fetch attempts failed (last: {last_error})")
    return None, "rpc_error"


def get_confirm_delay_s(default: float = 60.0) -> float:
    """Confirm-read delay from BRIDGE_CONFIRM_SECONDS (tests and callers may pass 0 directly)."""
    raw = os.getenv("BRIDGE_CONFIRM_SECONDS")
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        logging.getLogger(__name__).warning(f"BRIDGE_CONFIRM_SECONDS={raw!r} is not a number; using {default}s")
        return default


async def get_bridge_verdict(
    provider_builder: Callable[[int], "Web3 | None"],
    contract_address: str,
    deposit_id: int,
    reported: dict,
    *,
    confirm_delay_s: float | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    logger: Any = None,
) -> tuple[str, dict | None]:
    """Shared verdict discipline for Tier 1 and the reconciler: read, confirm, then decide.

    First read is hardened (retry + provider rotation + zero-struct sanity). A match is an
    immediate "ok". A zero struct or a mismatch waits `confirm_delay_s` then re-reads (the
    hardened fetch rotates providers); the confirm result is the verdict. A confirm RPC loss
    never resolves the row: it stays "unavailable" for the next retry.

    Returns:
        ("ok", trusted) | ("bad", trusted_or_None) | ("unavailable", None)

    """
    if logger is None:
        logger = logging.getLogger(__name__)
    if confirm_delay_s is None:
        confirm_delay_s = get_confirm_delay_s()

    deposit, kind = await fetch_deposit(provider_builder, contract_address, deposit_id, sanity=True, logger=logger)

    if kind != "ok" or deposit is None:
        if kind == "ok":  # unreachable today (fetch pairs "ok" with a tuple); belt for future changes
            kind = "rpc_error"
        if kind == "rpc_error":
            return "unavailable", None
    else:
        if trusted_dict(deposit) == reported:
            return "ok", trusted_dict(deposit)

    # zero struct or mismatch: confirm before calling the report bad. A lagging provider
    # can read zero seconds after the deposit landed; the 60s re-read is the guard.
    first = trusted_dict(deposit) if deposit is not None else None
    await sleep(confirm_delay_s)
    deposit2, kind2 = await fetch_deposit(provider_builder, contract_address, deposit_id, sanity=True, logger=logger)

    if kind2 == "rpc_error":
        return "unavailable", None
    if kind2 == "zero_struct":
        return "bad", None
    trusted2 = trusted_dict(deposit2)
    if trusted2 == reported:
        return "ok", trusted2
    return "bad", trusted2 or first


def make_provider_builder(chain_id: int, rpc_url: str | None = None, logger: Any = None) -> Callable[[int], Web3]:
    """Build the stream/reconciler provider factory with failover + TelliotConfig fallback.

    attempt > 0 invalidates the cached connection (a dead primary must not latch) and asks
    the connection manager to rotate to a different URL from EVM_RPC_URLS[_<chain_id>].
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    def provider_builder(attempt: int = 0) -> Web3:
        if attempt > 0:
            invalidate_web3_connection(chain_id)
        w3 = get_web3_connection(chain_id, custom_rpc_url=rpc_url, required=False, attempt=attempt)
        if w3 is None:
            logger.info(f"Falling back to TelliotConfig for chain {chain_id}")
            cfg = TelliotConfig()
            cfg.main.chain_id = chain_id
            endpoint = cfg.get_endpoint()
            endpoint.connect()
            return endpoint.web3
        return w3

    return provider_builder


async def get_trb_bridge_trusted_value(
    query_data: str, contract_address: str, chain_id: int = 1, rpc_url: str = None, logger: logging.Logger = None
) -> tuple[str, str, int, int] | None:
    """Get trusted value for TRBBridge query type by reading from deposits mapping.

    Thin wrapper over fetch_deposit keeping the historical (tuple | None) shape so existing
    callers don't churn. A zero-struct or a failed read returns None.

    Args:
        query_data: The query data containing deposit ID
        contract_address: Address of the TRBBridge contract
        chain_id: Chain ID for the contract (default: 1 for Ethereum mainnet)
        rpc_url: RPC URL for the bridge contract chain (if None, uses unified connection manager)
        logger: Logger instance

    Returns:
        Tuple of (eth_address, layer_address, amount, tip) from contract, or None if failed

    """
    if logger is None:
        logger = logging.getLogger(__name__)

    deposit_id = decode_query_data(query_data)
    if deposit_id is None:
        logger.error("Failed to decode deposit ID from query data")
        return None

    logger.info(f"Checking TRBBridge deposit ID: {deposit_id}")

    deposit, error_kind = await fetch_deposit(
        make_provider_builder(chain_id, rpc_url=rpc_url, logger=logger),
        contract_address,
        deposit_id,
        sanity=True,
        logger=logger,
    )
    if deposit is None:
        logger.error(f"Unable to fetch trusted value for deposit ID {deposit_id} ({error_kind})")
    return deposit
