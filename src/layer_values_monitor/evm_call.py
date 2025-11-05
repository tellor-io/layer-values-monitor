"""Trusted value for EVMCall query type."""

import math
from typing import Any

from layer_values_monitor.logger import logger

from hexbytes import HexBytes
from telliot_feeds.feeds import DataFeed
from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware import ExtraDataToPOAMiddleware


async def get_evm_call_trusted_value(reported_val: Any, feed: DataFeed, w3: Web3, chain_id: int) -> HexBytes:
    """Get trusted value for EVMCall query type.

    reported_val is already decoded as (encoded_value, timestamp) tuple by monitor.py
    w3 is a working Web3 connection to the target chain
    chain_id is the target chain ID for logging/verification
    """
    if not isinstance(reported_val, tuple):
        logger.warning(f"Expected tuple for EVMCall reported value, got {type(reported_val)}")
        return None

    if len(reported_val) != 2:
        logger.warning(f"Expected tuple of length 2(bytes, timestamp), got {len(reported_val)}")
        return None

    block_timestamp = reported_val[1]
    logger.info(
        f"EVMCall get_trusted_value - chain_id: {chain_id}, timestamp: {block_timestamp}, "
        f"contract: {feed.query.contractAddress}"
    )

    # Get block number using the provided Web3 connection
    block_number = get_block_number_at_timestamp(w3, block_timestamp, chain_id)
    if block_number is None:
        logger.error(f"Failed to get block number for timestamp {block_timestamp} on chain_id {chain_id}")
        return None

    logger.info(f"found block: {block_number} for timestamp: {block_timestamp}")

    # Make the contract call at the specific block
    try:
        contract_address = Web3.to_checksum_address(feed.query.contractAddress)
        logger.info(
            f"EVMCall eth_call (chain_id: {chain_id}) - contract: {contract_address}, "
            f"block: {block_number}, calldata: {feed.query.calldata.hex()}"
        )

        result = w3.eth.call({"to": contract_address, "data": feed.query.calldata}, block_identifier=block_number)

        logger.info(
            f"eth_call result (chain_id: {chain_id}): {result.hex() if result else 'empty'}, length: {len(result)} bytes"
        )

        # Return the raw eth_call result
        # monitor.py will decode the reported value to compare with this
        return HexBytes(result)
    except Exception as e:
        logger.error(f"Failed to fetch trusted value via eth_call on chain_id {chain_id}: {e}")
        return None


def get_block_number_at_timestamp(w3: Web3, timestamp: int, chain_id: int) -> int | None:
    """Get block number for a given timestamp using binary search.

    Returns block number or None on error.
    """
    current_block = w3.eth.block_number
    start_block = 0
    end_block = current_block

    while start_block <= end_block:
        midpoint = math.floor((start_block + end_block) / 2)
        # for poa chains get_block method throws an error if poa middleware is not injected
        try:
            block = w3.eth.get_block(midpoint)
        except ExtraDataLengthError:
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware(), layer=0)
            block = w3.eth.get_block(midpoint)

        if block.timestamp == timestamp:
            return midpoint
        elif block.timestamp < timestamp:
            start_block = midpoint + 1
        else:
            end_block = midpoint - 1

    # If we haven't found an exact match, interpolate between adjacent blocks
    block_a = w3.eth.get_block(end_block)
    block_b = w3.eth.get_block(start_block)

    block_delta = block_b.number - block_a.number
    timestamp_delta = block_b.timestamp - block_a.timestamp
    target_delta = timestamp - block_a.timestamp

    estimated_block_delta = target_delta * block_delta / timestamp_delta
    estimated_block_number = block_a.number + estimated_block_delta

    return int(estimated_block_number)
