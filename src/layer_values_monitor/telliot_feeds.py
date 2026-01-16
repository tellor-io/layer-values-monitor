"""Telliot Feeds helper functions."""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

from clamfig.base import Registry
from eth_abi import decode
from telliot_feeds.datafeed import DataFeed
from telliot_feeds.datasource import DataSource
from telliot_feeds.dtypes.datapoint import OptionalDataPoint
from telliot_feeds.feeds import CATALOG_FEEDS, DATAFEED_BUILDER_MAPPING
from telliot_feeds.queries.abi_query import AbiQuery
from telliot_feeds.queries.json_query import JsonQuery
from telliot_feeds.queries.query_catalog import query_catalog

logger = logging.getLogger(__name__)


# =============================================================================
# PRICE CACHE - Reduces redundant API calls (e.g., CoinGecko)
# =============================================================================

@dataclass
class CachedValue:
    """Cached price value with timestamp for TTL checking."""
    value: Any
    timestamp: float
    fetch_time: float  # When the value was fetched (for logging)


class PriceCache:
    """Thread-safe price cache with TTL to reduce redundant API calls.
    
    This cache stores trusted values by query_id with a configurable TTL.
    When multiple reports arrive for the same query_id within the TTL window,
    only one API call is made and the cached value is reused.
    """
    
    def __init__(self, ttl_seconds: float = 30.0, max_size: int = 1000):
        """Initialize the price cache.
        
        Args:
            ttl_seconds: Time-to-live for cached values in seconds. Default 30s.
            max_size: Maximum number of entries to store. Oldest entries are
                      evicted when this limit is reached.
        """
        self._cache: dict[str, CachedValue] = {}
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
        self._lock = asyncio.Lock()
    
    def _is_valid(self, entry: CachedValue) -> bool:
        """Check if a cached entry is still valid (within TTL)."""
        return (time.time() - entry.fetch_time) < self._ttl
    
    async def get(self, query_id: str) -> tuple[Any, float] | None:
        """Get a cached value if it exists and is still valid.
        
        Args:
            query_id: The query ID to look up
            
        Returns:
            Tuple of (value, timestamp) if cache hit, None if miss or expired
        """
        async with self._lock:
            entry = self._cache.get(query_id)
            if entry and self._is_valid(entry):
                self._hits += 1
                return (entry.value, entry.timestamp)
            
            # Remove expired entry if present
            if entry:
                del self._cache[query_id]
            
            self._misses += 1
            return None
    
    async def set(self, query_id: str, value: Any, timestamp: float) -> None:
        """Store a value in the cache.
        
        Args:
            query_id: The query ID to cache
            value: The trusted value to cache
            timestamp: The timestamp associated with the value
        """
        async with self._lock:
            # Evict oldest entries if at capacity
            if len(self._cache) >= self._max_size:
                # Remove oldest 10% of entries
                sorted_entries = sorted(
                    self._cache.items(), 
                    key=lambda x: x[1].fetch_time
                )
                entries_to_remove = max(1, len(sorted_entries) // 10)
                for key, _ in sorted_entries[:entries_to_remove]:
                    del self._cache[key]
            
            self._cache[query_id] = CachedValue(
                value=value,
                timestamp=timestamp,
                fetch_time=time.time()
            )
    
    async def invalidate(self, query_id: str) -> None:
        """Invalidate (remove) a cached entry.
        
        Args:
            query_id: The query ID to invalidate
        """
        async with self._lock:
            self._cache.pop(query_id, None)
    
    async def clear(self) -> None:
        """Clear all cached entries."""
        async with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dict with hits, misses, hit_rate, and size
        """
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%",
            "size": len(self._cache),
            "ttl_seconds": self._ttl,
        }


# Global price cache instance - 30 second TTL by default
# This is shared across all inspection paths to maximize cache hits
_price_cache = PriceCache(ttl_seconds=30.0)


def get_price_cache() -> PriceCache:
    """Get the global price cache instance."""
    return _price_cache


def set_cache_ttl(ttl_seconds: float) -> None:
    """Set the cache TTL. Useful for testing or configuration.
    
    Args:
        ttl_seconds: New TTL value in seconds
    """
    global _price_cache
    _price_cache._ttl = ttl_seconds


def get_query_from_data(query_data: bytes) -> AbiQuery | JsonQuery | None:
    """Get query give query data from telliot-feeds."""
    for q_type in (JsonQuery, AbiQuery):
        try:
            return q_type.get_query_from_data(query_data)
        except ValueError:
            pass
    return None


def get_query(query_data: str) -> AbiQuery | JsonQuery | None:
    """Fetch the registered query object from telliot-feeds.

    query_data: used to identifying the query
    return: AbiQuery or JsonQuery object
    """
    query_data_bytes = bytes.fromhex(query_data)
    query = get_query_from_data(query_data_bytes)
    return query


def get_feed_from_catalog(tag: str) -> DataFeed | None:
    """Get feed from telliot-feeds mapping if exists."""
    return CATALOG_FEEDS.get(tag)


def get_source_from_data(query_data: bytes, logger: logging) -> DataSource | None:
    """Recreate data source using query type thats decoded from query data field."""
    try:
        query_type, encoded_param_values = decode(["string", "bytes"], query_data)
    except OverflowError:
        logger.error("OverflowError while decoding query data.")
        return None
    try:
        cls = Registry.registry[query_type]
    except KeyError:
        logger.error(f"Unsupported query type: {query_type}")
        return None
    try:
        params_abi = cls.abi
    except AttributeError:
        logger.error(f"query type {query_type} doesn't have abi attirbute to decode params")
        return None
    param_names = [p["name"] for p in params_abi]
    param_types = [p["type"] for p in params_abi]
    param_values = decode(param_types, encoded_param_values)

    feed_builder = DATAFEED_BUILDER_MAPPING.get(query_type)
    if feed_builder is None:
        logger.error(f"query type {query_type} not supported by datafeed builder")
        return None

    source_class = feed_builder.source.__class__
    source = source_class()

    for key, value in zip(param_names, param_values, strict=False):
        setattr(source, key, value)
    return source


async def get_feed(query_id: str, query: AbiQuery | JsonQuery | None, logger: logging) -> DataFeed | None:
    """Get the current value for a query from API sources available in telliot-feeds.

    query_id: the hash of the query data used to fetch the value.
    query: query object that has the source and feed used to get value from relevant API.
    """
    if query is None:
        logger.warning(f"No query data found for query_id: {query_id}")
        return None

    catalog_entry = query_catalog.find(query_id=query_id)
    if len(catalog_entry) == 0:
        source = get_source_from_data(query_data=query.query_data, logger=logger)
        if source is None:
            logger.warning("no source found in telliot feeds found for query")
            return None
        return DataFeed(query=query, source=source)
    else:
        return get_feed_from_catalog(catalog_entry[0].tag)


async def fetch_value(feed: DataFeed) -> OptionalDataPoint:
    """Fetch the value from the data source in telliot-feeds.
    
    Note: This is the uncached version. For most use cases, prefer 
    fetch_value_cached() which reduces redundant API calls.
    """
    try:
        # Add timeout to prevent hanging on rate-limited APIs
        return await asyncio.wait_for(feed.source.fetch_new_datapoint(), timeout=15.0)
    except TimeoutError:
        error_msg = "Timeout fetching trusted value from telliot-feeds (15s)"
        logger.warning(error_msg)
        print(f"Error fetching trusted value from telliot-feeds: {error_msg}")  # print to terminal_log
        return None
    except Exception as e:
        error_msg = f"Error fetching trusted value from telliot-feeds: {e}"
        logger.warning(error_msg)
        print(error_msg)  # print to terminal_log
        return None


async def fetch_value_cached(
    feed: DataFeed, 
    query_id: str, 
    logger_instance: logging.Logger | None = None,
    force_refresh: bool = False
) -> OptionalDataPoint:
    """Fetch the value from telliot-feeds with caching to reduce API calls.
    
    This function checks the price cache first. If a valid cached value exists
    (within TTL), it returns that instead of making a new API call.
    
    Args:
        feed: The DataFeed to fetch from
        query_id: The query ID (used as cache key)
        logger_instance: Optional logger for cache hit/miss logging
        force_refresh: If True, bypass cache and fetch fresh value
        
    Returns:
        OptionalDataPoint tuple (value, timestamp) or None on error
    """
    cache = get_price_cache()
    log = logger_instance or logger
    
    # Check cache first (unless force_refresh)
    if not force_refresh:
        cached = await cache.get(query_id)
        if cached is not None:
            log.debug(f"💾 Cache HIT for {query_id[:16]}... (value: {cached[0]})")
            return cached
    
    # Cache miss or force refresh - fetch from API
    log.debug(f"🌐 Cache MISS for {query_id[:16]}... - fetching from API")
    result = await fetch_value(feed)
    
    if result is not None:
        value, timestamp = result
        # Store in cache
        await cache.set(query_id, value, timestamp)
        log.debug(f"💾 Cached value for {query_id[:16]}... (TTL: {cache._ttl}s)")
    
    return result


def extract_query_info(query: AbiQuery | JsonQuery | None, query_type: str | None = None) -> str:
    """Extract human-readable query information (e.g., asset pair) for discord messages.

    Args:
        query: Query object from telliot-feeds
        query_type: Optional query type string from the report

    Returns:
        str: Formatted query info (e.g., "BTC/USD", "EVMCall", "TRBBridge", etc.)

    """
    if query is None:
        return query_type or "Unknown"

    # Try to extract asset/currency for SpotPrice queries
    if hasattr(query, "asset") and hasattr(query, "currency"):
        return f"{query.asset}/{query.currency}"

    # Fall back to query type
    return getattr(query, "type", query_type or "Unknown")
