"""Regression tests for monitor behavior changes."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.custom_types import Metrics, NewReport
from layer_values_monitor.telliot_feeds import get_price_cache

import pytest


def make_spotprice_report() -> NewReport:
    """Create a representative SpotPrice report."""
    return NewReport(
        query_type="SpotPrice",
        query_data=(
            "0000000000000000000000000000000000000000000000000000000000000040"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000009"
            "53706f7450726963650000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000c0"
            "0000000000000000000000000000000000000000000000000000000000000040"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000003"
            "6574680000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000003"
            "7573640000000000000000000000000000000000000000000000000000000000"
        ),
        query_id="0xa6f013ee236804827b77696d350e9f0ac3e879328f2a3021d473a0b778ad78ac",
        value="0000000000000000000000000000000000000000000000000000000ba43b7400",
        aggregate_method="weighted-median",
        cyclelist="layer-1",
        power="1000",
        reporter="tellor1test",
        timestamp="1234567890000",
        meta_id="1",
        tx_hash="0xtest",
    )


@pytest.mark.asyncio
async def test_inspect_spotprice_path_alerts_on_stale_cache_before_refresh():
    """A stale cached value should still trigger the staleness alert before refresh."""
    from layer_values_monitor.monitor import inspect_spotprice_path

    report = make_spotprice_report()
    metrics = Metrics(
        metric="percentage",
        alert_threshold=0.01,
        warning_threshold=0.02,
        minor_threshold=0.05,
        major_threshold=0.10,
        pause_threshold=0.0,
    )
    config_watcher = MagicMock()
    config_watcher.has_query_config.return_value = True
    config_watcher.get_staleness_threshold.return_value = 540.0

    cache = get_price_cache()
    original_ttl = cache._ttl
    original_override = cache._ttl_override
    original_config_watcher = cache._config_watcher

    try:
        await cache.clear()
        cache._ttl = 180.0
        cache._ttl_override = None
        cache._config_watcher = None

        await cache.set(report.query_id, 99.0, time.time())
        cache._cache[report.query_id].fetch_time -= 600.0

        mock_query = MagicMock()
        mock_query.asset = "ETH"
        mock_query.currency = "USD"
        mock_query.value_type.decode.return_value = 100.0

        mock_feed = MagicMock()
        mock_feed.source.fetch_new_datapoint = AsyncMock(return_value=(101.0, time.time()))

        with patch("telliot_feeds.queries.query_catalog.query_catalog.find", return_value=[MagicMock()]):
            with patch("layer_values_monitor.monitor.get_query", return_value=mock_query):
                with patch("layer_values_monitor.monitor.get_feed", new=AsyncMock(return_value=mock_feed)):
                    with patch("layer_values_monitor.monitor.inspect", new=AsyncMock()):
                        with patch("layer_values_monitor.monitor.send_staleness_alert", new=AsyncMock()) as mock_alert:
                            await inspect_spotprice_path(
                                [report],
                                asyncio.Queue(),
                                config_watcher,
                                report.query_id,
                                report.query_data,
                                report.query_type,
                                metrics,
                                MagicMock(),
                            )

        mock_alert.assert_awaited_once()
    finally:
        await cache.clear()
        cache._ttl = original_ttl
        cache._ttl_override = original_override
        cache._config_watcher = original_config_watcher


@pytest.mark.asyncio
async def test_inspect_spotprice_path_only_alerts_once_until_refresh_succeeds():
    """Repeated stale reads should suppress duplicate alerts until the cache refreshes."""
    from layer_values_monitor.monitor import inspect_spotprice_path

    report = make_spotprice_report()
    metrics = Metrics(
        metric="percentage",
        alert_threshold=0.01,
        warning_threshold=0.02,
        minor_threshold=0.05,
        major_threshold=0.10,
        pause_threshold=0.0,
    )
    config_watcher = MagicMock()
    config_watcher.has_query_config.return_value = True
    config_watcher.get_staleness_threshold.return_value = 540.0

    cache = get_price_cache()
    original_ttl = cache._ttl
    original_override = cache._ttl_override
    original_config_watcher = cache._config_watcher

    try:
        await cache.clear()
        cache._ttl = 180.0
        cache._ttl_override = None
        cache._config_watcher = None

        await cache.set(report.query_id, 99.0, time.time())
        cache._cache[report.query_id].fetch_time -= 600.0
        cache._last_fetch_time[report.query_id] -= 600.0

        mock_query = MagicMock()
        mock_query.asset = "ETH"
        mock_query.currency = "USD"

        mock_feed = MagicMock()

        with patch("telliot_feeds.queries.query_catalog.query_catalog.find", return_value=[MagicMock()]):
            with patch("layer_values_monitor.monitor.get_query", return_value=mock_query):
                with patch("layer_values_monitor.monitor.get_feed", new=AsyncMock(return_value=mock_feed)):
                    with patch("layer_values_monitor.monitor.fetch_value_cached", new=AsyncMock(return_value=None)):
                        with patch("layer_values_monitor.monitor.send_staleness_alert", new=AsyncMock()) as mock_alert:
                            await inspect_spotprice_path(
                                [report],
                                asyncio.Queue(),
                                config_watcher,
                                report.query_id,
                                report.query_data,
                                report.query_type,
                                metrics,
                                MagicMock(),
                            )
                            await inspect_spotprice_path(
                                [report],
                                asyncio.Queue(),
                                config_watcher,
                                report.query_id,
                                report.query_data,
                                report.query_type,
                                metrics,
                                MagicMock(),
                            )

        mock_alert.assert_awaited_once()
    finally:
        await cache.clear()
        cache._ttl = original_ttl
        cache._ttl_override = original_override
        cache._config_watcher = original_config_watcher


@pytest.mark.asyncio
async def test_new_reports_queue_handler_counts_actual_reports_for_cache_logging():
    """Cache stats logging should trigger based on total reports, not query IDs."""
    from layer_values_monitor.monitor import new_reports_queue_handler

    new_reports_q = asyncio.Queue()
    disputes_q = asyncio.Queue()
    config_watcher = MagicMock()
    logger = MagicMock()

    batch = {f"query_{i}": [MagicMock(), MagicMock()] for i in range(50)}
    await new_reports_q.put(batch)

    mock_cache = MagicMock()
    mock_cache.get_stats = AsyncMock(
        return_value={"hits": 7, "misses": 3, "hit_rate": "70.0%", "size": 4, "ttl_seconds": 180.0}
    )

    with patch("layer_values_monitor.monitor.inspect_reports", new=AsyncMock()):
        with patch("layer_values_monitor.monitor.get_price_cache", return_value=mock_cache):
            task = asyncio.create_task(new_reports_queue_handler(new_reports_q, disputes_q, config_watcher, logger))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert any("Price cache stats" in str(call) for call in logger.info.call_args_list)
