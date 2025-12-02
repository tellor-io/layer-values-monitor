"""Unified EVM RPC connection manager with caching.

This module provides a centralized way to manage Web3 connections to EVM chains,
with connection caching to avoid redundant RPC connections.
"""

import logging
import os

from web3 import Web3

logger = logging.getLogger(__name__)

# Global cache for Web3 connections - shared across all modules
_web3_cache: dict[int, Web3] = {}


def get_web3_connection(
    chain_id: int,
    custom_rpc_url: str | None = None,
    required: bool = True,
) -> Web3 | None:
    """Get cached Web3 connection for any EVM chain with automatic failover.

    This function provides a unified way to connect to EVM chains with automatic
    caching and failover to backup RPC URLs.

    Lookup order:
    1. custom_rpc_url parameter (if provided, bypasses cache)
    2. Cached connection for chain_id (if exists)
    3. EVM_RPC_URLS_{chain_id} - comma-separated list (tries each in order)
    4. INFURA_API_KEY fallback (for chains 1, 11155111)

    Args:
        chain_id: Target chain ID (e.g., 1 for Ethereum mainnet, 11155111 for Sepolia)
        custom_rpc_url: Optional override RPC URL (bypasses cache and env vars)
        required: If True, log error when connection fails. Set to False for optional connections.

    Returns:
        Web3 instance with active connection, or None if connection fails

    Example:
        >>> # Comma-separated list - tries each in order until one works
        >>> # Env: EVM_RPC_URLS_11155111="https://primary.com,https://backup1.com,https://backup2.com"
        >>> w3 = get_web3_connection(11155111)
        >>> if w3:
        >>>     block = w3.eth.block_number

    """
    # Use custom URL if provided (bypass cache for one-time connections)
    if custom_rpc_url:
        try:
            w3 = Web3(Web3.HTTPProvider(custom_rpc_url))
            # Verify connection works
            _ = w3.eth.block_number
            logger.info(f"Created Web3 connection to chain {chain_id} via custom URL")
            return w3
        except Exception as e:
            if required:
                logger.error(f"Failed to connect to chain {chain_id} via custom URL {custom_rpc_url}: {e}")
            return None

    # Return cached connection if available
    if chain_id in _web3_cache:
        logger.debug(f"Using cached Web3 connection for chain {chain_id}")
        return _web3_cache[chain_id]

    # Build list of RPC URLs to try
    rpc_urls_to_try = []

    # Check for explicit chain-specific config first (takes precedence)
    urls_key = f"EVM_RPC_URLS_{chain_id}"
    urls_value = os.getenv(urls_key)

    if urls_value:
        # Parse comma-separated URLs
        urls = [url.strip() for url in urls_value.split(",") if url.strip()]
        for idx, url in enumerate(urls):
            label = "primary" if idx == 0 else f"backup{idx}"
            rpc_urls_to_try.append((url, label))
        logger.debug(f"Using explicit chain config for {chain_id}: {urls_key}")

    # If no explicit config, try Infura API key (simple default for common chains)
    if not rpc_urls_to_try:
        infura_key = os.getenv("INFURA_API_KEY")
        if infura_key:
            # Construct RPC URL based on chain_id for known Infura chains
            infura_rpc_urls = {
                1: f"https://mainnet.infura.io/v3/{infura_key}",
                11155111: f"https://sepolia.infura.io/v3/{infura_key}",
            }

            infura_url = infura_rpc_urls.get(chain_id)
            if infura_url:
                rpc_urls_to_try.append((infura_url, "Infura"))
                logger.debug(f"Using INFURA_API_KEY for chain {chain_id}")
            elif required:
                logger.error(
                    f"No RPC URL configured for chain {chain_id}. "
                    f"INFURA_API_KEY only supports chains: {list(infura_rpc_urls.keys())}. "
                    f"Set EVM_RPC_URLS_{chain_id} for other chains."
                )
                return None
        else:
            if required:
                logger.error(
                    f"No RPC URL configured for chain {chain_id}. "
                    f"Set INFURA_API_KEY (for chains 1, 11155111) or EVM_RPC_URLS_{chain_id} (comma-separated URLs)"
                )
            return None

    # Try each RPC URL in order until one works
    last_error = None
    for idx, (rpc_url, url_label) in enumerate(rpc_urls_to_try):
        try:
            provider = Web3.HTTPProvider(rpc_url)
            w3 = Web3(provider)

            # Verify connection works
            block_number = w3.eth.block_number
            actual_chain_id = w3.eth.chain_id

            # Verify chain ID matches (safety check)
            if actual_chain_id != chain_id:
                logger.warning(
                    f"Chain ID mismatch for {url_label} RPC: expected {chain_id}, got {actual_chain_id}. "
                    f"Caching under actual chain ID {actual_chain_id}"
                )
                chain_id = actual_chain_id

            # Cache the connection
            _web3_cache[chain_id] = w3

            # Log success with indication if using backup
            if idx == 0:
                logger.info(f"✅ Connected to chain {chain_id} via primary RPC (block: {block_number})")
            else:
                logger.warning(
                    f"⚠️ Connected to chain {chain_id} via {url_label} RPC (primary failed, block: {block_number})"
                )

            return w3

        except Exception as e:
            last_error = e
            logger.warning(f"Failed to connect to chain {chain_id} via {url_label} RPC: {e}")
            # Continue to next URL
            continue

    # All RPC URLs failed
    if required:
        logger.error(
            f"❌ Failed to connect to chain {chain_id} - all RPC endpoints failed. "
            f"Tried {len(rpc_urls_to_try)} URL(s). Last error: {last_error}"
        )

    return None


def get_saga_web3_connection(logger_instance: logging.Logger) -> tuple[Web3 | None, int | None]:
    """Get Web3 connection for Saga EVM with automatic failover support.

    Saga guardian functionality requires transaction signing, so it uses a dedicated
    env var (SAGA_RPC_URLS) separate from the standard EVM_RPC_URLS pattern.

    This function still leverages the global cache if the Saga chain ID matches
    an existing cached connection.

    Args:
        logger_instance: Logger instance for this operation

    Returns:
        Tuple of (Web3 instance, chain_id) or (None, None) if connection failed

    Example:
        >>> # Comma-separated list for Saga - tries each in order
        >>> # Env: SAGA_RPC_URLS="https://primary.saga.xyz,https://backup.saga.xyz"
        >>> w3, chain_id = get_saga_web3_connection(logger)
        >>> if w3:
        >>>     # Use for Saga guardian contract interactions
        >>>     manager = SagaContractManager(w3, private_key, logger)

    """
    # Get comma-separated list of Saga RPC URLs
    urls_value = os.getenv("SAGA_RPC_URLS")
    if not urls_value:
        logger_instance.warning("SAGA_RPC_URLS not set in environment - Saga guard disabled")
        return None, None

    # Parse comma-separated URLs
    urls = [url.strip() for url in urls_value.split(",") if url.strip()]
    if not urls:
        logger_instance.warning("SAGA_RPC_URLS is empty - Saga guard disabled")
        return None, None

    # Try each URL in order until one works
    last_error = None
    for idx, rpc_url in enumerate(urls):
        url_label = "primary" if idx == 0 else f"backup{idx}"
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url))

            # Verify connection and get chain ID
            block_number = w3.eth.block_number
            chain_id = w3.eth.chain_id

            # Cache this connection under its chain ID for potential reuse
            if chain_id not in _web3_cache:
                _web3_cache[chain_id] = w3

            # Log success with indication if using backup
            if idx == 0:
                logger_instance.info(f"✅ Connected to Saga EVM (chain {chain_id}) via primary RPC (block: {block_number})")
            else:
                logger_instance.warning(
                    f"⚠️ Connected to Saga EVM (chain {chain_id}) via {url_label} RPC (primary failed, block: {block_number})"
                )

            return w3, chain_id

        except Exception as e:
            last_error = e
            logger_instance.warning(f"Failed to connect to Saga EVM via {url_label} RPC: {e}")
            # Continue to next URL
            continue

    # All Saga RPC URLs failed
    logger_instance.error(
        f"❌ Failed to connect to Saga EVM - all RPC endpoints failed. Tried {len(urls)} URL(s). Last error: {last_error}"
    )
    return None, None


def validate_rpc_connection(
    rpc_url: str, network_name: str, logger_instance: logging.Logger
) -> tuple[bool, str, int | None]:
    """Validate RPC URL connectivity and retrieve chain information.

    Used during startup to verify that configured RPC endpoints are accessible
    and responding correctly.

    Args:
        rpc_url: The RPC endpoint URL to validate
        network_name: Human-readable network name for logging (e.g., "Ethereum", "Saga")
        logger_instance: Logger instance for this operation

    Returns:
        Tuple of (is_valid, error_message, chain_id)
        - is_valid: True if connection successful
        - error_message: Empty string if valid, error description if invalid
        - chain_id: The chain ID returned by the RPC, or None if connection failed

    Example:
        >>> is_valid, error, chain_id = validate_rpc_connection(
        ...     "https://sepolia.infura.io/v3/key",
        ...     "Ethereum Sepolia",
        ...     logger
        ... )
        >>> if not is_valid:
        >>>     raise ValueError(error)

    """
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))

        # Test basic connectivity
        block_number = w3.eth.block_number
        chain_id = w3.eth.chain_id

        # Validate chain ID is reasonable
        if chain_id <= 0:
            return False, f"Invalid chain ID {chain_id} for {network_name} network", None

        logger_instance.info(f"✅ {network_name} RPC validation successful - Chain ID: {chain_id}, Block: {block_number}")
        return True, "", chain_id

    except Exception as e:
        error_msg = f"Failed to connect to {network_name} RPC at {rpc_url}: {e}"
        return False, error_msg, None


def clear_cache() -> None:
    """Clear all cached Web3 connections.

    Useful for testing or when you need to force reconnection with fresh settings.
    """
    global _web3_cache
    _web3_cache.clear()
    logger.info("Cleared all cached Web3 connections")


def get_cached_chain_ids() -> list[int]:
    """Get list of chain IDs that have cached connections.

    Returns:
        List of chain IDs with active cached connections

    Example:
        >>> cached = get_cached_chain_ids()
        >>> print(f"Active connections: {cached}")
        Active connections: [1, 11155111]

    """
    return list(_web3_cache.keys())
