"""Test double-check dispute logic for SpotPrice queries."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from layer_values_monitor.custom_types import Metrics, NewReport


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
async def test_double_check_both_cross_threshold(sample_report, metrics):
    """Test that dispute proceeds when both checks cross threshold."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    first_trusted_value = 90.0  # 11.1% diff - crosses major threshold
    second_trusted_value = 88.0  # 13.6% diff - crosses major threshold
    
    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()
    
    # Mock fetcher that returns second trusted value
    async def mock_fetcher():
        return (second_trusted_value, 1234567890)
    
    # Execute
    with patch('layer_values_monitor.monitor.generic_alert') as mock_alert:
        await inspect(
            sample_report,
            reported_value,
            first_trusted_value,
            disputes_q,
            metrics,
            mock_logger,
            query=mock_query,
            trusted_value_fetcher=mock_fetcher
        )
    
    # Verify dispute was added to queue
    assert not disputes_q.empty()
    dispute = await disputes_q.get()
    assert dispute.reporter == sample_report.reporter
    assert dispute.query_id == sample_report.query_id
    
    # Verify Discord alert was sent with both values
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    assert "Second inspection triggered: sending dispute" in alert_msg
    assert str(first_trusted_value) in alert_msg
    assert str(second_trusted_value) in alert_msg


@pytest.mark.asyncio
async def test_double_check_second_does_not_cross(sample_report, metrics):
    """Test that dispute is cancelled when second check doesn't cross threshold."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    first_trusted_value = 90.0  # 11.1% diff - crosses major threshold
    second_trusted_value = 99.0  # 1.01% diff - does NOT cross warning threshold (2%)
    
    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()
    
    # Mock fetcher that returns second trusted value
    async def mock_fetcher():
        return (second_trusted_value, 1234567890)
    
    # Execute
    with patch('layer_values_monitor.monitor.generic_alert') as mock_alert:
        await inspect(
            sample_report,
            reported_value,
            first_trusted_value,
            disputes_q,
            metrics,
            mock_logger,
            query=mock_query,
            trusted_value_fetcher=mock_fetcher
        )
    
    # Verify NO dispute was added to queue
    assert disputes_q.empty()
    
    # Verify Discord alert was sent with both values
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    assert "was past the first trusted value, but not the second" in alert_msg
    assert str(first_trusted_value) in alert_msg
    assert str(second_trusted_value) in alert_msg


@pytest.mark.asyncio
async def test_single_check_mode_without_fetcher(sample_report, metrics):
    """Test that single-check mode works when no fetcher is provided (EVMCall, TRBBridge)."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    trusted_value = 90.0  # 11.1% diff - crosses major threshold
    
    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    
    # Execute without fetcher (should use single-check logic)
    with patch('layer_values_monitor.monitor.generic_alert') as mock_alert:
        await inspect(
            sample_report,
            reported_value,
            trusted_value,
            disputes_q,
            metrics,
            mock_logger,
            query=None,
            trusted_value_fetcher=None  # No fetcher - single check mode
        )
    
    # Verify dispute was added to queue (single check)
    assert not disputes_q.empty()
    dispute = await disputes_q.get()
    assert dispute.reporter == sample_report.reporter
    
    # Verify standard alert was sent
    mock_alert.assert_called_once()
    alert_msg = mock_alert.call_args[0][0]
    assert "Second inspection triggered" not in alert_msg


@pytest.mark.asyncio
async def test_fetcher_error_cancels_dispute(sample_report, metrics):
    """Test that dispute is cancelled if second fetch fails."""
    from layer_values_monitor.monitor import inspect

    # Setup
    reported_value = 100.0
    first_trusted_value = 90.0  # 11.1% diff - crosses major threshold
    
    disputes_q = asyncio.Queue()
    mock_logger = Mock()
    mock_query = Mock()
    
    # Mock fetcher that raises an error
    async def mock_fetcher():
        raise Exception("API Error")
    
    # Execute
    with patch('layer_values_monitor.monitor.generic_alert') as mock_alert:
        await inspect(
            sample_report,
            reported_value,
            first_trusted_value,
            disputes_q,
            metrics,
            mock_logger,
            query=mock_query,
            trusted_value_fetcher=mock_fetcher
        )
    
    # Verify NO dispute was added (error cancels dispute)
    assert disputes_q.empty()
    
    # Verify error was logged
    assert any("Error fetching second trusted value" in str(call) for call in mock_logger.error.call_args_list)

