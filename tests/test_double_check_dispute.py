"""Test double-check dispute logic for SpotPrice queries.

The flow is:
1. Compare reported value against CACHED trusted value
2. If threshold crossed → immediately fetch fresh trusted value
3. If fresh value still crosses threshold → wait 10s → fetch final value
4. Only dispute if final check still crosses threshold
"""

import asyncio
from unittest.mock import Mock, patch

from layer_values_monitor.custom_types import Metrics, NewReport

import pytest


@pytest.fixture
def sample_report():
    """Create a sample report for testing."""
    return NewReport(
        query_type="SpotPrice",
        query_data="0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000953706f745072696365000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003657468000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000037573640000000000000000000000000000000000000000000000000000000000",
        query_id="0xa6f013ee236804827b77696d350e9f0ac3e879328f2a3021d473a0b778ad78ac",
        value="0x0000000000000000000000000000000000000000000000000000000ba43b7400",
        aggregate_method="weighted-median",
        cyclelist="layer-1",
        power="1000",
        reporter="tellor1test",
        timestamp="1234567890000",
        meta_id="1",
        tx_hash="0xtest",
    )


@pytest.fixture
def metrics():
    """Create metrics with percentage-based thresholds."""
    return Metrics(
        metric="percentage",
        alert_threshold=0.01,  # 1%
        warning_threshold=0.02,  # 2%
        minor_threshold=0.05,  # 5%
        major_threshold=0.10,  # 10%
        pause_threshold=0.0,
    )


@pytest.mark.asyncio
async def test_triple_check_all_cross_threshold(sample_report, metrics):
    """Test that dispute proceeds when all checks cross threshold.

    Flow: cached (90.0) → immediate refresh (88.0) → final (87.0) → dispute
    """
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    cached_trusted_value = 90.0  # 11.1% diff - crosses major threshold

    # Fetcher returns different values for immediate refresh and final check
    fetch_call_count = 0

    async def mock_fetcher():
        nonlocal fetch_call_count
        fetch_call_count += 1
        if fetch_call_count == 1:
            return (88.0, 1234567890)  # Immediate refresh: 13.6% diff - still crosses
        else:
            return (87.0, 1234567891)  # Final check: 14.9% diff - still crosses

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()

    # Execute with patched sleep to speed up test
    with patch("layer_values_monitor.monitor.generic_alert") as mock_alert:
        with patch("layer_values_monitor.monitor.asyncio.sleep", return_value=None):
            await inspect(
                sample_report,
                reported_value,
                cached_trusted_value,
                disputes_q,
                metrics,
                mock_logger,
                query=mock_query,
                trusted_value_fetcher=mock_fetcher,
            )

    # Verify dispute was added to queue
    assert not disputes_q.empty()
    dispute = await disputes_q.get()
    assert dispute.reporter == sample_report.reporter
    assert dispute.query_id == sample_report.query_id

    # Verify fetcher was called twice (immediate + final)
    assert fetch_call_count == 2

    # Verify Discord alert was sent
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    # Should show first (cached) and second (final) trusted values
    assert "First Trusted Value" in alert_msg
    assert "Second Trusted Value" in alert_msg
    assert str(cached_trusted_value) in alert_msg
    assert "87.0" in alert_msg  # Final trusted value
    # Verify it's the dispute version
    alert_desc = mock_alert.call_args[1].get("description", "")
    assert "ATTEMPTING TO SEND DISPUTE" in alert_desc


@pytest.mark.asyncio
async def test_immediate_refresh_clears_dispute(sample_report, metrics):
    """Test that dispute is cancelled when immediate refresh doesn't cross threshold.

    This tests the case where the cached value was stale and the fresh value is fine.
    Flow: cached (90.0) → immediate refresh (99.5) → NO 10s delay, NO dispute
    """
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    cached_trusted_value = 90.0  # 11.1% diff - crosses major threshold

    # Fetcher returns value that doesn't cross threshold
    fetch_call_count = 0

    async def mock_fetcher():
        nonlocal fetch_call_count
        fetch_call_count += 1
        return (99.5, 1234567890)  # 0.5% diff - does NOT cross any threshold

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()

    # Execute - should NOT wait 10s since immediate refresh clears it
    with patch("layer_values_monitor.monitor.generic_alert") as mock_alert:
        with patch("layer_values_monitor.monitor.asyncio.sleep") as mock_sleep:
            await inspect(
                sample_report,
                reported_value,
                cached_trusted_value,
                disputes_q,
                metrics,
                mock_logger,
                query=mock_query,
                trusted_value_fetcher=mock_fetcher,
            )
            # Should NOT have waited 10s since immediate refresh cleared
            mock_sleep.assert_not_called()

    # Verify NO dispute was added to queue
    assert disputes_q.empty()

    # Verify fetcher was only called once (immediate refresh only)
    assert fetch_call_count == 1

    # Alert should still be sent (alertable but not disputable after refresh)
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    assert "First Trusted Value" in alert_msg
    assert "Second Trusted Value" in alert_msg
    assert str(cached_trusted_value) in alert_msg
    assert "99.5" in alert_msg


@pytest.mark.asyncio
async def test_zero_cached_trusted_value_sends_alert_and_skips_dispute(sample_report, metrics):
    """Test that a zero cached trusted value sends an alert and skips inspection."""
    from layer_values_monitor.monitor import inspect

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()
    mock_query.type = "SpotPrice"

    with patch("layer_values_monitor.monitor.generic_alert") as mock_alert:
        await inspect(
            sample_report,
            100.0,
            0.0,
            disputes_q,
            metrics,
            mock_logger,
            query=mock_query,
            trusted_value_fetcher=None,
        )

    assert disputes_q.empty()
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    alert_desc = mock_alert.call_args[1].get("description", "")
    assert sample_report.query_id in alert_msg
    assert "Trusted value for" in alert_msg
    assert "was 0" in alert_msg
    assert "TRUSTED VALUE WAS 0" in alert_desc


@pytest.mark.asyncio
async def test_zero_immediate_refresh_value_sends_alert_and_cancels_dispute(sample_report, metrics):
    """Test that a zero immediate refresh value sends an alert and cancels the dispute."""
    from layer_values_monitor.monitor import inspect

    async def mock_fetcher():
        return (0.0, 1234567890)

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()
    mock_query.type = "SpotPrice"

    with patch("layer_values_monitor.monitor.generic_alert") as mock_alert:
        with patch("layer_values_monitor.monitor.asyncio.sleep") as mock_sleep:
            await inspect(
                sample_report,
                100.0,
                90.0,
                disputes_q,
                metrics,
                mock_logger,
                query=mock_query,
                trusted_value_fetcher=mock_fetcher,
            )
            mock_sleep.assert_not_called()

    assert disputes_q.empty()
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    alert_desc = mock_alert.call_args[1].get("description", "")
    assert sample_report.query_id in alert_msg
    assert "Trusted value for" in alert_msg
    assert "was 0" in alert_msg
    assert "TRUSTED VALUE WAS 0" in alert_desc


@pytest.mark.asyncio
async def test_zero_final_refresh_value_sends_alert_and_cancels_dispute(sample_report, metrics):
    """Test that a zero final refresh value sends an alert and cancels the dispute."""
    from layer_values_monitor.monitor import inspect

    fetch_call_count = 0

    async def mock_fetcher():
        nonlocal fetch_call_count
        fetch_call_count += 1
        if fetch_call_count == 1:
            return (88.0, 1234567890)
        return (0.0, 1234567891)

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()
    mock_query.type = "SpotPrice"

    with patch("layer_values_monitor.monitor.generic_alert") as mock_alert:
        with patch("layer_values_monitor.monitor.asyncio.sleep", return_value=None):
            await inspect(
                sample_report,
                100.0,
                90.0,
                disputes_q,
                metrics,
                mock_logger,
                query=mock_query,
                trusted_value_fetcher=mock_fetcher,
            )

    assert disputes_q.empty()
    assert fetch_call_count == 2
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    alert_desc = mock_alert.call_args[1].get("description", "")
    assert sample_report.query_id in alert_msg
    assert "Trusted value for" in alert_msg
    assert "was 0" in alert_msg
    assert "TRUSTED VALUE WAS 0" in alert_desc


@pytest.mark.asyncio
async def test_final_check_clears_dispute(sample_report, metrics):
    """Test that dispute is cancelled when final check doesn't cross threshold.

    Flow: cached (90.0) → immediate refresh (88.0) → 10s → final (99.5) → NO dispute
    """
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    cached_trusted_value = 90.0  # 11.1% diff - crosses major threshold

    # Fetcher returns bad value first, then good value
    fetch_call_count = 0

    async def mock_fetcher():
        nonlocal fetch_call_count
        fetch_call_count += 1
        if fetch_call_count == 1:
            return (88.0, 1234567890)  # Immediate: 13.6% diff - crosses
        else:
            return (99.5, 1234567891)  # Final: 0.5% diff - does NOT cross

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()

    # Execute
    with patch("layer_values_monitor.monitor.generic_alert") as mock_alert:
        with patch("layer_values_monitor.monitor.asyncio.sleep", return_value=None):
            await inspect(
                sample_report,
                reported_value,
                cached_trusted_value,
                disputes_q,
                metrics,
                mock_logger,
                query=mock_query,
                trusted_value_fetcher=mock_fetcher,
            )

    # Verify NO dispute was added to queue
    assert disputes_q.empty()

    # Verify fetcher was called twice
    assert fetch_call_count == 2

    # Verify Discord alert was sent with both values
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    assert "First Trusted Value" in alert_msg
    assert "Second Trusted Value" in alert_msg
    # Verify it's the NO dispute version
    alert_desc = mock_alert.call_args[1].get("description", "")
    assert "NO DISPUTE SENT" in alert_desc


@pytest.mark.asyncio
async def test_single_check_mode_without_fetcher(sample_report, metrics):
    """Test that single-check mode works when no fetcher is provided (TRBBridge)."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    trusted_value = 90.0  # 11.1% diff - crosses major threshold

    disputes_q = asyncio.Queue()
    mock_logger = Mock()

    # Execute without fetcher (should use single-check logic)
    with patch("layer_values_monitor.monitor.generic_alert") as mock_alert:
        await inspect(
            sample_report,
            reported_value,
            trusted_value,
            disputes_q,
            metrics,
            mock_logger,
            query=None,
            trusted_value_fetcher=None,  # No fetcher - single check mode
        )

    # Verify dispute was added to queue (single check)
    assert not disputes_q.empty()
    dispute = await disputes_q.get()
    assert dispute.reporter == sample_report.reporter

    # Verify standard alert was sent
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    assert "Second Trusted Value" not in alert_msg


@pytest.mark.asyncio
async def test_fetcher_error_on_immediate_refresh_cancels_dispute(sample_report, metrics):
    """Test that dispute is cancelled if immediate refresh fails."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    cached_trusted_value = 90.0  # 11.1% diff - crosses major threshold

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()

    # Mock fetcher that raises an error on first call
    async def mock_fetcher():
        raise Exception("API Error")

    # Execute
    with patch("layer_values_monitor.monitor.generic_alert"):
        await inspect(
            sample_report,
            reported_value,
            cached_trusted_value,
            disputes_q,
            metrics,
            mock_logger,
            query=mock_query,
            trusted_value_fetcher=mock_fetcher,
        )

    # Verify NO dispute was added (error cancels dispute)
    assert disputes_q.empty()

    # Verify error was logged
    assert any("Error during dispute verification" in str(call) for call in mock_logger.error.call_args_list)


@pytest.mark.asyncio
async def test_fetcher_error_on_final_check_cancels_dispute(sample_report, metrics):
    """Test that dispute is cancelled if final check fetch fails."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    cached_trusted_value = 90.0  # 11.1% diff - crosses major threshold

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()

    # Mock fetcher that succeeds first time, fails second time
    fetch_call_count = 0

    async def mock_fetcher():
        nonlocal fetch_call_count
        fetch_call_count += 1
        if fetch_call_count == 1:
            return (88.0, 1234567890)  # Immediate: crosses threshold
        else:
            raise Exception("API Error on final check")

    # Execute
    with patch("layer_values_monitor.monitor.generic_alert"):
        with patch("layer_values_monitor.monitor.asyncio.sleep", return_value=None):
            await inspect(
                sample_report,
                reported_value,
                cached_trusted_value,
                disputes_q,
                metrics,
                mock_logger,
                query=mock_query,
                trusted_value_fetcher=mock_fetcher,
            )

    # Verify NO dispute was added (error cancels dispute)
    assert disputes_q.empty()

    # Verify error was logged
    assert any("Error during dispute verification" in str(call) for call in mock_logger.error.call_args_list)


@pytest.mark.asyncio
async def test_fetcher_returns_none_cancels_dispute(sample_report, metrics):
    """Test that dispute is cancelled if fetcher returns None."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    cached_trusted_value = 90.0  # 11.1% diff - crosses major threshold

    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()

    # Mock fetcher that returns None
    async def mock_fetcher():
        return None

    # Execute
    with patch("layer_values_monitor.monitor.generic_alert"):
        await inspect(
            sample_report,
            reported_value,
            cached_trusted_value,
            disputes_q,
            metrics,
            mock_logger,
            query=mock_query,
            trusted_value_fetcher=mock_fetcher,
        )

    # Verify NO dispute was added
    assert disputes_q.empty()

    # Verify error was logged
    assert any("Failed to fetch fresh trusted value" in str(call) for call in mock_logger.error.call_args_list)
