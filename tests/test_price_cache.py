"""Tests for the price cache functionality."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from layer_values_monitor.telliot_feeds import (
    PriceCache,
    fetch_value_cached,
    get_price_cache,
    set_cache_ttl,
)


class TestPriceCache:
    """Test cases for PriceCache class."""

    @pytest.fixture
    def cache(self):
        """Create a fresh cache for each test."""
        return PriceCache(ttl_seconds=1.0, max_size=10)

    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self, cache):
        """Test that cache miss returns None."""
        result = await cache.get("nonexistent_query_id")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_set_and_get(self, cache):
        """Test setting and getting a cached value."""
        query_id = "test_query_123"
        value = 100.5
        timestamp = time.time()

        await cache.set(query_id, value, timestamp)
        result = await cache.get(query_id)

        assert result is not None
        assert result[0] == value
        assert result[1] == timestamp

    @pytest.mark.asyncio
    async def test_cache_expiration(self, cache):
        """Test that cached values expire after TTL."""
        query_id = "test_query_123"
        await cache.set(query_id, 100.5, time.time())

        # Value should be present immediately
        result = await cache.get(query_id)
        assert result is not None

        # Wait for TTL to expire (1 second + buffer)
        await asyncio.sleep(1.1)

        # Value should be expired
        result = await cache.get(query_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, cache):
        """Test manually invalidating a cached entry."""
        query_id = "test_query_123"
        await cache.set(query_id, 100.5, time.time())

        # Value should be present
        result = await cache.get(query_id)
        assert result is not None

        # Invalidate the entry
        await cache.invalidate(query_id)

        # Value should be gone
        result = await cache.get(query_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_clear(self, cache):
        """Test clearing all cached entries."""
        # Add multiple entries
        for i in range(5):
            await cache.set(f"query_{i}", i * 10.0, time.time())

        # All entries should be present
        for i in range(5):
            result = await cache.get(f"query_{i}")
            assert result is not None

        # Clear the cache
        await cache.clear()

        # All entries should be gone
        for i in range(5):
            result = await cache.get(f"query_{i}")
            assert result is None

    @pytest.mark.asyncio
    async def test_cache_eviction_on_max_size(self, cache):
        """Test that oldest entries are evicted when max size is reached."""
        # Fill the cache beyond max_size (10)
        for i in range(15):
            await cache.set(f"query_{i}", i * 10.0, time.time())
            await asyncio.sleep(0.01)  # Small delay to ensure different fetch times

        # Cache should have evicted some entries
        stats = cache.get_stats()
        assert stats["size"] <= 10

    def test_cache_stats(self, cache):
        """Test cache statistics."""
        stats = cache.get_stats()
        assert "hits" in stats
        assert "misses" in stats
        assert "hit_rate" in stats
        assert "size" in stats
        assert "ttl_seconds" in stats

    @pytest.mark.asyncio
    async def test_cache_hit_rate_tracking(self, cache):
        """Test that hit rate is tracked correctly."""
        query_id = "test_query_123"
        await cache.set(query_id, 100.5, time.time())

        # One miss
        await cache.get("nonexistent")

        # Two hits
        await cache.get(query_id)
        await cache.get(query_id)

        stats = cache.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert "66.7%" in stats["hit_rate"]


class TestFetchValueCached:
    """Test cases for fetch_value_cached function."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger."""
        return MagicMock()

    @pytest.mark.asyncio
    async def test_cache_miss_fetches_from_api(self, mock_logger):
        """Test that cache miss triggers API fetch."""
        # Clear cache first
        cache = get_price_cache()
        await cache.clear()

        # Use unique query_id to avoid cache interference
        query_id = f"test_query_miss_{time.time()}"
        mock_feed = MagicMock()
        mock_feed.source.fetch_new_datapoint = AsyncMock(return_value=(100.5, time.time()))

        result = await fetch_value_cached(mock_feed, query_id, mock_logger)

        assert result is not None
        assert result[0] == 100.5
        mock_feed.source.fetch_new_datapoint.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_hit_skips_api_fetch(self, mock_logger):
        """Test that cache hit skips API fetch."""
        # Clear cache first
        cache = get_price_cache()
        await cache.clear()

        # Use unique query_id to avoid cache interference
        query_id = f"test_query_hit_{time.time()}"
        mock_feed = MagicMock()
        mock_feed.source.fetch_new_datapoint = AsyncMock(return_value=(100.5, time.time()))

        # First call - cache miss
        result1 = await fetch_value_cached(mock_feed, query_id, mock_logger)
        assert mock_feed.source.fetch_new_datapoint.call_count == 1

        # Second call - cache hit (should use same mock_feed)
        result2 = await fetch_value_cached(mock_feed, query_id, mock_logger)
        assert mock_feed.source.fetch_new_datapoint.call_count == 1  # Still 1, not 2

        # Results should be the same
        assert result1[0] == result2[0]

    @pytest.mark.asyncio
    async def test_force_refresh_bypasses_cache(self, mock_logger):
        """Test that force_refresh bypasses the cache."""
        # Clear cache first
        cache = get_price_cache()
        await cache.clear()

        # Use unique query_id to avoid cache interference
        query_id = f"test_query_force_{time.time()}"
        mock_feed = MagicMock()
        mock_feed.source.fetch_new_datapoint = AsyncMock(return_value=(100.5, time.time()))

        # First call - cache miss
        await fetch_value_cached(mock_feed, query_id, mock_logger)
        assert mock_feed.source.fetch_new_datapoint.call_count == 1

        # Second call with force_refresh - should fetch again
        await fetch_value_cached(mock_feed, query_id, mock_logger, force_refresh=True)
        assert mock_feed.source.fetch_new_datapoint.call_count == 2

    @pytest.mark.asyncio
    async def test_api_error_returns_none(self, mock_logger):
        """Test that API error returns None and doesn't cache."""
        # Clear cache first
        cache = get_price_cache()
        await cache.clear()

        # Use unique query_id to avoid cache interference
        query_id = f"test_query_error_{time.time()}"
        feed = MagicMock()
        feed.source.fetch_new_datapoint = AsyncMock(side_effect=Exception("API Error"))

        with patch("layer_values_monitor.telliot_feeds.fetch_value", return_value=None):
            result = await fetch_value_cached(feed, query_id, mock_logger)

        assert result is None


class TestGlobalCache:
    """Test cases for global cache functions."""

    def test_get_price_cache_returns_same_instance(self):
        """Test that get_price_cache returns the same instance."""
        cache1 = get_price_cache()
        cache2 = get_price_cache()
        assert cache1 is cache2

    def test_set_cache_ttl(self):
        """Test setting the cache TTL."""
        original_ttl = get_price_cache()._ttl
        try:
            set_cache_ttl(60.0)
            assert get_price_cache()._ttl == 60.0
        finally:
            # Restore original TTL
            set_cache_ttl(original_ttl)
