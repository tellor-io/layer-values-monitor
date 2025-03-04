"""Trusted value for EVMCall query type."""

import math
from typing import Any

from layer_values_monitor.logger import logger

from hexbytes import HexBytes
from telliot_core.apps.telliot_config import TelliotConfig
from telliot_feeds.feeds import DataFeed
from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware import geth_poa_middleware


async def get_evm_call_trusted_value(reported_val: Any, feed: DataFeed) -> HexBytes:
    """Get trusted value for EVMCall query type."""
    if not isinstance(reported_val, tuple):
        return True
    block_timestamp = reported_val[1]
    reported_val = HexBytes(reported_val[0])

    block_number = get_block_number_at_timestamp(feed.query.chainId, block_timestamp)

    trusted_val, _ = await feed.source.fetch_new_datapoint(block_number)
    if not isinstance(trusted_val, tuple):
        logger.warning(f"Bad value response for EVMCall: {trusted_val}")
        return None

    if trusted_val[0] is None:
        logger.warning(f"Unable to fetch trusted value for EVMCall: {trusted_val}")
        return None
    return HexBytes(trusted_val[0])


def get_block_number_at_timestamp(chain_id: int, timestamp: int) -> int | None:
    """Get block number for a given timestamp from the identified rpc."""
    cfg = TelliotConfig()
    cfg.main.chain_id = chain_id
    try:
        endpoint = cfg.get_endpoint()
        endpoint.connect()
    except ValueError as e:
        logger.error(f"Unable to connect to endpoint on chain_id {cfg.main.chain_id}: {e}")
        return None

    w3: Web3 = endpoint.web3

    current_block = w3.eth.block_number
    start_block = 0
    end_block = current_block

    while start_block <= end_block:
        midpoint = math.floor((start_block + end_block) / 2)
        # for poa chains get_block method throws an error if poa middleware is not injected
        try:
            block = w3.eth.get_block(midpoint)
        except ExtraDataLengthError:
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
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
