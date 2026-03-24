import asyncio
import time
from unittest.mock import Mock, patch

from layer_values_monitor.custom_types import NewReport
from layer_values_monitor.main import ConfigWatcher, watch_config

import pytest


def test_init(config_file, config_watcher):
    """Test the initialization of ConfigWatcher."""
    assert isinstance(config_watcher, ConfigWatcher)
    assert config_watcher.config_path == config_file
    assert config_watcher.last_modified_time > 0


def test_config_structure(config_watcher):
    """Test that config is correctly loaded with new structure."""
    assert "percentage" in config_watcher.global_defaults
    assert "spotprice" in config_watcher.query_types
    assert "spotprice" in config_watcher.query_configs

    # Test query type info
    query_type_info = config_watcher.get_query_type_info("spotprice")
    assert query_type_info is not None
    assert query_type_info["metric"] == "percentage"
    assert query_type_info["handler"] == "telliot_feeds"

    # Test query config
    query_config = config_watcher.get_query_config("test_query_id", "spotprice")
    assert query_config.get("alert_threshold") == 0.05


def test_reload_config_when_changed(config_file, config_watcher):
    """Test that config is reloaded when file changes."""
    # Record initial timestamp
    initial_timestamp = config_watcher.last_modified_time

    # Wait a bit to ensure file timestamp will be different
    time.sleep(0.1)

    # Modify config file
    with open(config_file, "w") as f:
        f.write("""
            [global_defaults.percentage]
            alert_threshold = 0.2
            warning_threshold = 0.3
            
            [query_types]
            spotprice = { metric = "percentage", handler = "telliot_feeds" }
            
            [queries.spotprice.test_query_id]
            alert_threshold = 0.15
        """)

    # Reload config
    reloaded = config_watcher.reload_config()

    # Check that reload happened
    assert reloaded is True
    assert config_watcher.last_modified_time > initial_timestamp

    # Check that config was updated
    assert config_watcher.global_defaults["percentage"]["alert_threshold"] == 0.2
    query_config = config_watcher.get_query_config("test_query_id", "spotprice")
    assert query_config["alert_threshold"] == 0.15


def test_reload_config_when_unchanged(config_watcher):
    """Test that reload returns False when file hasn't changed."""
    # Call reload_config once to set initial state
    config_watcher.reload_config()

    # Call again without changing the file
    reloaded = config_watcher.reload_config()

    # Should return False as file hasn't changed
    assert reloaded is False


@pytest.mark.asyncio
async def test_watch_config(config_file, config_watcher):
    """Test the watch_config async function."""
    # Set a very short check interval for testing
    check_interval = 0.1

    # Create a task for watch_config with a short timeout
    task = asyncio.create_task(watch_config(config_watcher, check_interval))

    # Wait a bit to let watch_config run
    await asyncio.sleep(check_interval * 2)

    # Record the current state
    initial_timestamp = config_watcher.last_modified_time
    initial_threshold = config_watcher.global_defaults["percentage"]["alert_threshold"]

    # Modify config file
    with open(config_file, "w") as f:
        f.write("""
            [global_defaults.percentage]
            alert_threshold = 0.99
            warning_threshold = 0.25
            
            [query_types]
            spotprice = { metric = "percentage", handler = "telliot_feeds" }
            
            [queries.spotprice.test_query_id]
            alert_threshold = 0.05
        """)

    # Wait for watch_config to detect the change
    await asyncio.sleep(check_interval * 2)

    # Cancel the task
    task.cancel()

    try:
        await task
    except asyncio.CancelledError:
        pass

    # Verify that config was automatically updated
    assert config_watcher.last_modified_time > initial_timestamp
    assert config_watcher.global_defaults["percentage"]["alert_threshold"] != initial_threshold
    assert config_watcher.global_defaults["percentage"]["alert_threshold"] == 0.99


def test_has_query_config(config_watcher):
    """Test has_query_config method."""
    assert config_watcher.has_query_config("test_query_id", "spotprice") is True
    assert config_watcher.has_query_config("nonexistent", "spotprice") is False
    assert config_watcher.has_query_config("test_query_id", "wrongtype") is False


def test_find_query_config(config_watcher):
    """Test find_query_config method."""
    # Should find the config
    config = config_watcher.find_query_config("test_query_id")
    assert config.get("alert_threshold") == 0.05

    # Should return empty dict for nonexistent query
    config = config_watcher.find_query_config("nonexistent")
    assert config == {}


def test_get_metrics_for_query(config_watcher):
    """Test get_metrics_for_query with inheritance."""
    metrics = config_watcher.get_metrics_for_query("test_query_id", "spotprice")
    assert metrics is not None
    assert metrics.metric == "percentage"
    assert metrics.alert_threshold == 0.05  # Overridden
    assert metrics.warning_threshold == 0.25  # From global defaults
    assert metrics.minor_threshold == 0.99  # From global defaults


def test_is_supported_query_type(config_watcher):
    """Test is_supported_query_type method."""
    assert config_watcher.is_supported_query_type("spotprice") is True
    assert config_watcher.is_supported_query_type("SpotPrice") is True  # Case insensitive
    assert config_watcher.is_supported_query_type("unknown") is False


def test_uses_telliot_catalog(config_watcher):
    """Test uses_telliot_catalog method."""
    assert config_watcher.uses_telliot_catalog("spotprice") is True
    assert config_watcher.uses_telliot_catalog("unknown") is False


def test_is_deprecated_query_type(config_file):
    """Test is_deprecated_query_type detects the deprecated flag."""
    with open(config_file, "w") as f:
        f.write("""
            [global_defaults.equality]
            alert_threshold = 1.0

            [query_types]
            trbbridge = { metric = "equality", handler = "trb_bridge", deprecated = true }
            trbbridgev2 = { metric = "equality", handler = "trb_bridge" }
            spotprice = { metric = "percentage", handler = "telliot_feeds" }
        """)

    time.sleep(0.1)
    watcher = ConfigWatcher(config_file)

    assert watcher.is_deprecated_query_type("trbbridge") is True
    assert watcher.is_deprecated_query_type("TRBBridge") is True  # case insensitive
    assert watcher.is_deprecated_query_type("trbbridgev2") is False
    assert watcher.is_deprecated_query_type("spotprice") is False
    assert watcher.is_deprecated_query_type("nonexistent") is False


def test_deprecated_flag_hot_reload(config_file):
    """Test that deprecated flag is picked up on config reload."""
    with open(config_file, "w") as f:
        f.write("""
            [global_defaults.equality]
            alert_threshold = 1.0

            [query_types]
            trbbridge = { metric = "equality", handler = "trb_bridge" }
        """)

    time.sleep(0.1)
    watcher = ConfigWatcher(config_file)
    assert watcher.is_deprecated_query_type("trbbridge") is False

    time.sleep(0.1)
    with open(config_file, "w") as f:
        f.write("""
            [global_defaults.equality]
            alert_threshold = 1.0

            [query_types]
            trbbridge = { metric = "equality", handler = "trb_bridge", deprecated = true }
        """)

    reloaded = watcher.reload_config()
    assert reloaded is True
    assert watcher.is_deprecated_query_type("trbbridge") is True


@pytest.mark.asyncio
async def test_inspect_reports_skips_deprecated_query_type(config_file):
    """Test that inspect_reports sends alert and skips inspection for deprecated types."""
    from layer_values_monitor.monitor import inspect_reports

    with open(config_file, "w") as f:
        f.write("""
            [global_defaults.equality]
            alert_threshold = 1.0

            [query_types]
            trbbridge = { metric = "equality", handler = "trb_bridge", deprecated = true }
            trbbridgev2 = { metric = "equality", handler = "trb_bridge" }
        """)

    time.sleep(0.1)
    watcher = ConfigWatcher(config_file)

    report = NewReport(
        query_type="TRBBridge",
        query_data="0xabc",
        query_id="0x123",
        value="0xdeadbeef",
        aggregate_method="weighted-median",
        cyclelist="layer-1",
        power="1000",
        reporter="layer1testreporter",
        timestamp="1234567890000",
        meta_id="1",
        tx_hash="0xtesthash",
    )

    disputes_q = asyncio.Queue()
    mock_logger = Mock()

    with patch("layer_values_monitor.monitor.deprecated_query_type_alert") as mock_alert:
        await inspect_reports([report], disputes_q, watcher, mock_logger)

    # Alert should have been sent
    mock_alert.assert_called_once_with(
        query_type="TRBBridge",
        query_id="0x123",
        report_value="0xdeadbeef",
        reporter="layer1testreporter",
        tx_hash="0xtesthash",
    )

    # No disputes should be queued
    assert disputes_q.empty()

    # Logger should show warning about deprecated type
    mock_logger.warning.assert_called_once()
    assert "deprecated" in mock_logger.warning.call_args.args[0].lower()


@pytest.mark.asyncio
async def test_inspect_reports_does_not_skip_non_deprecated(config_file):
    """Test that non-deprecated types proceed to normal inspection."""
    from layer_values_monitor.monitor import inspect_reports

    with open(config_file, "w") as f:
        f.write("""
            [global_defaults.equality]
            alert_threshold = 1.0

            [query_types]
            trbbridge = { metric = "equality", handler = "trb_bridge", deprecated = true }
            trbbridgev2 = { metric = "equality", handler = "trb_bridge" }
        """)

    time.sleep(0.1)
    watcher = ConfigWatcher(config_file)

    report = NewReport(
        query_type="TRBBridgeV2",
        query_data="0xabc",
        query_id="0x456",
        value="0xcafe",
        aggregate_method="weighted-median",
        cyclelist="layer-1",
        power="1000",
        reporter="layer1reporter",
        timestamp="1234567890000",
        meta_id="2",
        tx_hash="0xhash2",
    )

    disputes_q = asyncio.Queue()
    mock_logger = Mock()

    with patch("layer_values_monitor.monitor.deprecated_query_type_alert") as mock_dep_alert:
        with patch("layer_values_monitor.monitor.inspect_trbbridge_path") as mock_bridge:
            await inspect_reports([report], disputes_q, watcher, mock_logger)

    # Deprecated alert should NOT have been called
    mock_dep_alert.assert_not_called()

    # Normal bridge inspection should have been called
    mock_bridge.assert_called_once()
