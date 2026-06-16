"""Tests for the price cache functionality."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.telliot_feeds import (
    CacheResult,
    PriceCache,
    fetch_value_cached,
    get_price_cache,
    initialize_cache_with_config,
    set_cache_ttl,
)

import pytest


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
        stats = await cache.get_stats()
        assert stats["size"] <= 10

    @pytest.mark.asyncio
    async def test_cache_stats(self, cache):
        """Test cache statistics."""
        stats = await cache.get_stats()
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

        stats = await cache.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert "66.7%" in stats["hit_rate"]

    @pytest.mark.asyncio
    async def test_get_with_staleness_returns_cache_result(self, cache):
        """Test that get_with_staleness returns CacheResult with staleness info."""
        query_id = "test_query_staleness"
        value = 100.5
        timestamp = time.time()

        await cache.set(query_id, value, timestamp)

        result = await cache.get_with_staleness(query_id)

        assert result is not None
        assert isinstance(result, CacheResult)
        assert result.value == value
        assert result.timestamp == timestamp
        assert result.age_seconds < 1.0  # Should be very fresh
        assert result.is_stale is False  # Default staleness threshold is 3x TTL (3 seconds)

    @pytest.mark.asyncio
    async def test_get_with_staleness_detects_stale_cache(self, cache):
        """Test that get_with_staleness correctly identifies stale cache."""
        query_id = "test_query_stale"

        # Set cache with TTL of 1 second, staleness threshold is 3x = 3 seconds
        await cache.set(query_id, 100.5, time.time())

        # Wait for cache to become stale (> 3 seconds)
        await asyncio.sleep(3.5)

        result = await cache.get_with_staleness(query_id)

        assert result is not None
        assert result.is_stale is True
        assert result.age_seconds >= 3.0

    @pytest.mark.asyncio
    async def test_get_with_staleness_returns_none_for_missing(self, cache):
        """Test that get_with_staleness returns None for missing entries."""
        result = await cache.get_with_staleness("nonexistent_query")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_with_staleness_does_not_change_cache_stats(self, cache):
        """Test that staleness inspection does not affect hit/miss counters."""
        query_id = "test_query_stats"
        await cache.set(query_id, 100.5, time.time())

        await cache.get_with_staleness(query_id)
        await cache.get_with_staleness("missing_query")

        stats = await cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0

    @pytest.mark.asyncio
    async def test_get_age_returns_correct_age(self, cache):
        """Test that get_age returns the correct age in seconds."""
        query_id = "test_query_age"
        await cache.set(query_id, 100.5, time.time())

        await asyncio.sleep(0.5)

        age = await cache.get_age(query_id)

        assert age is not None
        assert 0.4 < age < 1.0  # Should be around 0.5 seconds

    @pytest.mark.asyncio
    async def test_get_age_returns_none_for_missing(self, cache):
        """Test that get_age returns None for missing entries."""
        age = await cache.get_age("nonexistent_query")
        assert age is None

    @pytest.mark.asyncio
    async def test_stale_alert_state_cooldown_expires(self, cache):
        """Stale alert suppression expires after the 5-minute cooldown window."""
        from layer_values_monitor.telliot_feeds import STALE_ALERT_COOLDOWN

        query_id = "test_query_stale_alert"

        await cache.mark_stale_alerted(query_id)
        assert await cache.is_stale_alerted(query_id) is True

        # Manually backdate the alert time past the cooldown window
        cache._stale_state[query_id]["last_alert_time"] -= STALE_ALERT_COOLDOWN + 1

        assert await cache.is_stale_alerted(query_id) is False

    @pytest.mark.asyncio
    async def test_stale_state_persists_after_cache_set(self, cache):
        """Stale state is retained after a cache.set() so recovery can be triggered."""
        query_id = "test_query_stale_persist"

        await cache.mark_stale_alerted(query_id)
        assert await cache.is_stale_alerted(query_id) is True

        # A fresh value arriving should NOT clear stale tracking
        await cache.set(query_id, 100.5, time.time())

        assert query_id in cache._stale_state

    @pytest.mark.asyncio
    async def test_stale_recovery_waits_for_episode_and_freshness_windows(self, cache):
        """Recovery is eligible only after a long-enough stale episode and freshness window."""
        from layer_values_monitor.telliot_feeds import STALE_ALERT_COOLDOWN, STALE_RECOVERY_WINDOW

        query_id = "test_query_stale_recovery"

        await cache.mark_stale_alerted(query_id)
        assert await cache.should_send_recovery(query_id) is False

        cache._stale_state[query_id]["first_alert_time"] -= STALE_RECOVERY_WINDOW + 1
        assert await cache.should_send_recovery(query_id) is False

        cache._stale_state[query_id]["last_stale_seen"] -= STALE_ALERT_COOLDOWN + 1
        assert await cache.should_send_recovery(query_id) is True

        await cache.mark_recovery_sent(query_id)
        assert await cache.should_send_recovery(query_id) is False

    @pytest.mark.asyncio
    async def test_get_refresh_candidates_only_returns_active_entries_near_ttl(self, cache):
        """Only active queries near TTL expiry should be proactively refreshed."""
        query_id = "test_query_refresh_candidate"
        inactive_query_id = "test_query_inactive"
        query_type = "spotprice"
        feed = MagicMock()
        inactive_feed = MagicMock()

        await cache.set(query_id, 100.5, time.time())
        await cache.register_feed(query_id, feed, query_type)
        await cache.record_report_activity(query_id, query_type)
        cache._last_fetch_time[query_id] -= 0.9

        await cache.set(inactive_query_id, 101.5, time.time())
        await cache.register_feed(inactive_query_id, inactive_feed, query_type)
        await cache.record_report_activity(inactive_query_id, query_type)
        cache._last_fetch_time[inactive_query_id] -= 0.9
        cache._last_report_time[inactive_query_id] -= 4.0

        candidates = await cache.get_refresh_candidates(0.8)

        assert candidates == [(query_id, feed, query_type)]


class TestPerQueryTTL:
    """Test cases for per-query TTL configuration."""

    @pytest.fixture
    def mock_config_watcher(self):
        """Create a mock config watcher with per-query TTL settings."""
        mock = MagicMock()
        # Default check interval
        mock.get_check_interval.return_value = 180.0
        mock.get_staleness_threshold.return_value = 540.0  # 3x default
        return mock

    @pytest.fixture
    def cache_with_config(self, mock_config_watcher):
        """Create a cache with config watcher attached."""
        cache = PriceCache(ttl_seconds=180.0, max_size=10)
        cache.set_config_watcher(mock_config_watcher)
        return cache

    @pytest.mark.asyncio
    async def test_per_query_ttl_override(self, cache_with_config, mock_config_watcher):
        """Test that per-query TTL overrides are respected."""
        query_id = "test_query_custom_ttl"
        query_type = "spotprice"

        # Configure mock to return custom TTL for this query
        def custom_interval(qid=None, qtype=None):
            if qid == query_id and qtype == query_type:
                return 60.0  # 60 second TTL for this query
            return 180.0  # Default

        mock_config_watcher.get_check_interval.side_effect = custom_interval

        # Set value
        await cache_with_config.set(query_id, 100.5, time.time())

        # Should be valid immediately
        result = await cache_with_config.get(query_id, query_type)
        assert result is not None

        # Verify the custom TTL was used
        ttl = cache_with_config._get_ttl_for_query(query_id, query_type)
        assert ttl == 60.0

    def test_ttl_fallback_without_config_watcher(self):
        """Test that TTL falls back to default without config watcher."""
        cache = PriceCache(ttl_seconds=180.0)

        ttl = cache._get_ttl_for_query("any_query", "spotprice")
        assert ttl == 180.0  # Should use default

    def test_global_ttl_uses_latest_config_without_query_type(self, cache_with_config, mock_config_watcher):
        """Test that default TTL follows live config changes when no override is set."""
        assert cache_with_config._get_ttl_for_query("any_query") == 180.0
        assert cache_with_config._get_staleness_threshold("any_query") == 540.0

        mock_config_watcher.get_check_interval.return_value = 60.0
        mock_config_watcher.get_staleness_threshold.return_value = 180.0

        assert cache_with_config._get_ttl_for_query("any_query") == 60.0
        assert cache_with_config._get_staleness_threshold("any_query") == 180.0

    def test_ttl_override_beats_reloaded_config_defaults(self, cache_with_config, mock_config_watcher):
        """Test that explicit TTL overrides are not replaced by config defaults."""
        cache_with_config._ttl = 45.0
        cache_with_config._ttl_override = 45.0
        mock_config_watcher.get_check_interval.return_value = 60.0
        mock_config_watcher.get_staleness_threshold.return_value = 180.0

        assert cache_with_config._get_ttl_for_query("any_query") == 45.0
        assert cache_with_config._get_staleness_threshold("any_query") == 135.0


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
    async def test_concurrent_misses_share_one_api_call(self, mock_logger):
        """Test that concurrent cache misses share a single API fetch."""
        cache = get_price_cache()
        await cache.clear()

        query_id = f"test_query_concurrent_{time.time()}"
        mock_feed = MagicMock()

        async def slow_fetch():
            await asyncio.sleep(0.05)
            return (100.5, time.time())

        mock_feed.source.fetch_new_datapoint = AsyncMock(side_effect=slow_fetch)

        results = await asyncio.gather(*[fetch_value_cached(mock_feed, query_id, mock_logger) for _ in range(5)])

        assert mock_feed.source.fetch_new_datapoint.call_count == 1
        assert all(result == results[0] for result in results)

    @pytest.mark.asyncio
    async def test_failed_shared_fetch_can_retry(self, mock_logger):
        """Test that a failed shared fetch clears in-flight state for retries."""
        cache = get_price_cache()
        await cache.clear()

        query_id = f"test_query_retry_{time.time()}"
        feed = MagicMock()

        with patch(
            "layer_values_monitor.telliot_feeds.fetch_value",
            new=AsyncMock(side_effect=[None, (100.5, 1234567890.0)]),
        ) as mock_fetch_value:
            first_results = await asyncio.gather(*[fetch_value_cached(feed, query_id, mock_logger) for _ in range(2)])
            second_result = await fetch_value_cached(feed, query_id, mock_logger)

        assert first_results == [None, None]
        assert second_result == (100.5, 1234567890.0)
        assert mock_fetch_value.await_count == 2

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

    @pytest.mark.asyncio
    async def test_fetch_value_cached_registers_feed_and_report_activity(self, mock_logger):
        """fetch_value_cached should keep feed metadata for proactive refreshes."""
        cache = get_price_cache()
        await cache.clear()

        query_id = f"test_query_activity_{time.time()}"
        query_type = "spotprice"
        feed = MagicMock()
        feed.source.fetch_new_datapoint = AsyncMock(return_value=(100.5, time.time()))

        await fetch_value_cached(feed, query_id, mock_logger, query_type=query_type)

        assert cache._feeds[query_id] is feed
        assert cache._query_types[query_id] == query_type
        assert query_id in cache._last_report_time
        assert query_id in cache._last_fetch_time


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
        original_override = get_price_cache()._ttl_override
        try:
            set_cache_ttl(60.0)
            assert get_price_cache()._ttl == 60.0
        finally:
            # Restore original TTL state without forcing a new override.
            get_price_cache()._ttl = original_ttl
            get_price_cache()._ttl_override = original_override

    def test_initialize_cache_with_config(self):
        """Test initializing cache with config watcher."""
        mock_config = MagicMock()
        mock_config.get_check_interval.return_value = 120.0

        original_ttl = get_price_cache()._ttl
        original_config = get_price_cache()._config_watcher
        original_override = get_price_cache()._ttl_override

        try:
            get_price_cache()._ttl_override = None
            initialize_cache_with_config(mock_config)

            cache = get_price_cache()
            assert cache._config_watcher is mock_config
            assert cache._ttl == 120.0
        finally:
            # Restore original state
            get_price_cache()._ttl = original_ttl
            get_price_cache()._config_watcher = original_config
            get_price_cache()._ttl_override = original_override


class TestCacheWithQueryType:
    """Test cases for cache operations with query_type parameter."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger."""
        return MagicMock()

    @pytest.mark.asyncio
    async def test_fetch_value_cached_with_query_type(self, mock_logger):
        """Test that fetch_value_cached passes query_type to cache."""
        cache = get_price_cache()
        await cache.clear()

        query_id = f"test_query_type_{time.time()}"
        query_type = "spotprice"
        mock_feed = MagicMock()
        mock_feed.source.fetch_new_datapoint = AsyncMock(return_value=(100.5, time.time()))

        # First call with query_type
        result = await fetch_value_cached(mock_feed, query_id, mock_logger, query_type=query_type)

        assert result is not None
        assert result[0] == 100.5

        # Second call should hit cache
        result2 = await fetch_value_cached(mock_feed, query_id, mock_logger, query_type=query_type)

        # Should only have called API once
        assert mock_feed.source.fetch_new_datapoint.call_count == 1
        assert result[0] == result2[0]
