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
    
    encoded_value = reported_val[0]
    block_timestamp = reported_val[1]
    
    logger.info(f"EVMCall get_trusted_value - chain_id: {chain_id}, timestamp: {block_timestamp}, contract: {feed.query.contractAddress}")

    # Get block number using the provided Web3 connection
    block_number = get_block_number_at_timestamp(w3, block_timestamp, chain_id)
    if block_number is None:
        logger.error(f"Failed to get block number for timestamp {block_timestamp} on chain_id {chain_id}")
        return None
    
    logger.info(f"found block: {block_number} for timestamp: {block_timestamp}")
    
    # Make the contract call at the specific block
    try:
        # Verify we're on the right chain
        actual_chain_id = w3.eth.chain_id
        logger.info(f"EVMCall VERIFICATION - expected chain_id: {chain_id}, w3.eth.chain_id: {actual_chain_id}")
        if actual_chain_id != chain_id:
            logger.error(f"CHAIN MISMATCH! Expected {chain_id} but Web3 is connected to {actual_chain_id}")
        
        # Convert address to checksum format (web3.py requirement)
        contract_address = Web3.to_checksum_address(feed.query.contractAddress)
        
        logger.info(f"EVMCall eth_call (chain_id: {chain_id}) - contract: {contract_address}, block: {block_number}, calldata: {feed.query.calldata.hex()}")
        
        result = w3.eth.call(
            {
                'to': contract_address,
                'data': feed.query.calldata
            },
            block_identifier=block_number
        )
        
        logger.info(f"eth_call result (chain_id: {chain_id}): {result.hex() if result else 'empty'}, length: {len(result)} bytes")
        
        # Return the raw eth_call result
        # monitor.py will decode the reported value to compare with this
        return HexBytes(result)
    except Exception as e:
        logger.error(f"Failed to fetch trusted value via eth_call on chain_id {chain_id}: {e}")
        return None


def get_web3_connection(chain_id: int) -> Web3 | None:
    """Get Web3 connection for a given chain_id using INFURA_API_KEY from env.
    
    Returns Web3 instance or None on error.
    """
    import os
    
    # Get Infura API key from environment
    infura_key = os.getenv("INFURA_API_KEY")
    if not infura_key:
        logger.error(f"INFURA_API_KEY not found in environment variables for chain_id {chain_id}")
        return None
    
    # Construct RPC URL based on chain_id
    rpc_urls = {
        1: f"https://mainnet.infura.io/v3/{infura_key}",
        11155111: f"https://sepolia.infura.io/v3/{infura_key}",
    }
    
    rpc_url = rpc_urls.get(chain_id)
    if not rpc_url:
        logger.error(f"No RPC URL configured for chain_id {chain_id}. Supported: {list(rpc_urls.keys())}")
        return None
    
    try:
        provider = Web3.HTTPProvider(rpc_url)
        w3 = Web3(provider)
        logger.info(f"successfully created Web3 instance for chain_id: {chain_id}")
        return w3
    except Exception as e:
        logger.error(f"Unable to connect to RPC for chain_id {chain_id}: {e}")
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