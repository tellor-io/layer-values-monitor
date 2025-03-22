import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.monitor import (
    Metrics,
    Msg,
    inspect_reports,
    listen_to_new_report_events,
)

import pytest
import websockets


@pytest.fixture
def sample_config(config_watcher):
    config_watcher.config = {
        "query1": {
            "metric": "percentage",
            "alert_threshold": 0.1,
            "warning_threshold": 0.2,
            "minor_threshold": 0.3,
            "major_threshold": 0.4,
        }
    }
    return config_watcher


@pytest.fixture
def global_thresholds():
    return {
        "global_percentage_alert_threshold": 0.15,
        "global_percentage_warning_threshold": 0.25,
        "global_percentage_minor_threshold": 0.35,
        "global_percentage_major_threshold": 0.45,
        "global_range_alert_threshold": 10.0,
        "global_range_warning_threshold": 20.0,
        "global_range_minor_threshold": 30.0,
        "global_range_major_threshold": 40.0,
        "global_equality_warning_threshold": 1.0,
        "global_equality_minor_threshold": 1.0,
        "global_equality_major_threshold": 1.0,
    }


@pytest.fixture
def sample_valid_report():
    return json.dumps(
        {
            "result": {
                "events": {
                    "new_report.query_type": ["percentage"],
                    "new_report.query_data": ["0123456789abcdef"],
                    "new_report.query_id": ["query1"],
                    "new_report.value": ["0123456789abcdef"],
                    "new_report.aggregate_method": ["median"],
                    "new_report.cyclelist": ["cycle1"],
                    "new_report.reporter_power": ["1000"],
                    "new_report.reporter": ["reporter1"],
                    "new_report.timestamp": ["1234567890"],
                    "new_report.meta_id": ["meta1"],
                    "tx.hash": ["0xabcdef123456"],
                }
            }
        }
    )


@pytest.fixture
def sample_valid_evmcall_report():
    return json.dumps(
        {
            "result": {
                "events": {
                    "new_report.query_type": ["evmcall"],
                    "new_report.query_data": ["0123456789abcdef"],
                    "new_report.query_id": ["query2"],
                    "new_report.value": ["0123456789abcdef"],
                    "new_report.aggregate_method": ["median"],
                    "new_report.cyclelist": ["cycle1"],
                    "new_report.reporter_power": ["1000"],
                    "new_report.reporter": ["reporter1"],
                    "new_report.timestamp": ["1234567890"],
                    "new_report.meta_id": ["meta1"],
                    "tx.hash": ["0xabcdef123456"],
                }
            }
        }
    )


@pytest.fixture
def sample_missing_result_report():
    return json.dumps({"other_field": "value"})


@pytest.fixture
def sample_missing_events_report():
    return json.dumps({"result": {"other_field": "value"}})


@pytest.fixture
def sample_malformed_report():
    return json.dumps(
        {
            "result": {
                "events": {
                    "new_report.query_type": [],  # Empty list will cause IndexError
                    "new_report.query_data": ["0123456789abcdef"],
                    "new_report.query_id": ["query1"],
                    "new_report.value": ["0123456789abcdef"],
                    "new_report.aggregate_method": ["median"],
                    "new_report.cyclelist": ["cycle1"],
                    "new_report.reporter_power": ["1000"],
                    "new_report.reporter": ["reporter1"],
                    "new_report.timestamp": ["1234567890"],
                    "new_report.meta_id": ["meta1"],
                    "tx.hash": ["0xabcdef123456"],
                }
            }
        }
    )


@pytest.mark.asyncio
async def test_inspect_reports_valid_percentage_disputable(sample_config, global_thresholds, sample_valid_report):
    """Test inspect_reports with a valid percentage report that is disputable."""
    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()

    await reports_queue.put(sample_valid_report)

    with (
        patch("layer_values_monitor.monitor.get_metric") as mock_get_metric,
        patch("layer_values_monitor.monitor.get_query_from_data") as mock_get_query,
        patch("layer_values_monitor.monitor.query_catalog.find") as mock_find,
        patch("layer_values_monitor.monitor.get_feed_from_catalog") as mock_get_feed,
        patch("layer_values_monitor.monitor.is_disputable") as mock_is_disputable,
        patch("layer_values_monitor.monitor.determine_dispute_category") as mock_determine_category,
        patch("layer_values_monitor.monitor.determine_dispute_fee") as mock_determine_fee,
        patch("layer_values_monitor.monitor.generic_alert") as mock_generate_msg,
        patch("layer_values_monitor.monitor.add_to_table") as mock_add_to_table,
    ):
        # Configure mocks
        mock_query = MagicMock()
        mock_query.value_type.decode.return_value = 105.0
        mock_get_query.return_value = mock_query

        mock_find.return_value = [MagicMock(tag="tag1")]

        mock_feed = MagicMock()
        mock_source = AsyncMock()
        mock_source.fetch_new_datapoint.return_value = (100.0, None)
        mock_feed.source = mock_source
        mock_get_feed.return_value = mock_feed

        mock_get_metric.return_value = Metrics(
            metric="percentage", alert_threshold=0.1, warning_threshold=0.2, minor_threshold=0.3, major_threshold=0.4
        )

        mock_is_disputable.return_value = (True, True, 0.05)

        mock_determine_category.return_value = "warning"
        mock_determine_fee.return_value = 0.1

        await inspect_reports(reports_queue, disputes_queue, sample_config, max_iterations=1, **global_thresholds)

        mock_get_query.assert_called_once()
        mock_find.assert_called_once()
        mock_get_feed.assert_called_once()
        mock_source.fetch_new_datapoint.assert_called_once()
        mock_is_disputable.assert_called_once_with("percentage", 0.1, 0.2, 105.0, 100.0)
        mock_generate_msg.assert_called_once()
        mock_determine_category.assert_called_once()
        mock_determine_fee.assert_called_once()
        mock_add_to_table.assert_called_once()

        # Check if dispute was added to queue
        assert not disputes_queue.empty()
        dispute_msg = await disputes_queue.get()
        assert isinstance(dispute_msg, Msg)
        assert dispute_msg.reporter == "reporter1"
        assert dispute_msg.query_id == "query1"
        assert dispute_msg.category == "warning"
        assert dispute_msg.fee == "0.1loya"


@pytest.mark.asyncio
async def test_inspect_reports_evmcall(sample_config, global_thresholds, sample_valid_evmcall_report):
    """Test inspect_reports with an EVMCall report."""
    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()
    # Add report
    await reports_queue.put(sample_valid_evmcall_report)

    with (
        patch("layer_values_monitor.monitor.get_metric") as mock_get_metric,
        patch("layer_values_monitor.monitor.get_query_from_data") as mock_get_query,
        patch("layer_values_monitor.monitor.query_catalog.find") as mock_find,
        patch("layer_values_monitor.monitor.get_feed_from_catalog") as mock_get_feed,
        patch("layer_values_monitor.monitor.is_disputable") as mock_is_disputable,
        patch("layer_values_monitor.monitor.get_evm_call_trusted_value") as mock_get_evm_call,
        patch("layer_values_monitor.monitor.determine_dispute_category") as mock_determine_category,
        patch("layer_values_monitor.monitor.determine_dispute_fee") as mock_determine_fee,
        patch("layer_values_monitor.monitor.generic_alert") as mock_generate_msg,
        patch("layer_values_monitor.monitor.add_to_table") as mock_add_to_table,
    ):
        mock_query = MagicMock()
        mock_query.value_type.decode.return_value = "0xresult"
        mock_get_query.return_value = mock_query

        mock_find.return_value = [MagicMock(tag="tag1")]

        mock_feed = MagicMock()
        mock_get_feed.return_value = mock_feed

        # For EVMCall, we'll use get_evm_call_trusted_value instead of fetch_new_datapoint
        mock_get_evm_call.return_value = "0xexpected"

        mock_get_metric.return_value = Metrics(
            metric="equality",
            alert_threshold=1.0,
            warning_threshold=global_thresholds["global_equality_warning_threshold"],
            minor_threshold=global_thresholds["global_equality_minor_threshold"],
            major_threshold=global_thresholds["global_equality_major_threshold"],
        )

        mock_is_disputable.return_value = (True, True, 1.0)

        mock_determine_category.return_value = "major"
        mock_determine_fee.return_value = 0.5

        # Run the function with a single iteration
        await inspect_reports(reports_queue, disputes_queue, sample_config, max_iterations=1, **global_thresholds)

        mock_get_metric.assert_called_once()
        mock_get_query.assert_called_once()
        mock_find.assert_called_once()
        mock_get_feed.assert_called_once()
        mock_get_evm_call.assert_called_once_with("0xresult", mock_feed)
        mock_is_disputable.assert_called_once_with(
            "equality", 1.0, global_thresholds["global_equality_warning_threshold"], "0xresult", "0xexpected"
        )
        mock_generate_msg.assert_called_once()
        mock_determine_category.assert_called_once()
        mock_determine_fee.assert_called_once()
        mock_add_to_table.assert_called_once()

        # Check if dispute was added to queue
        assert not disputes_queue.empty()
        dispute_msg = await disputes_queue.get()
        assert isinstance(dispute_msg, Msg)
        assert dispute_msg.reporter == "reporter1"
        assert dispute_msg.query_id == "query2"
        assert dispute_msg.category == "major"
        assert dispute_msg.fee == "0.5loya"


@pytest.mark.asyncio
async def test_inspect_reports_missing_result(sample_config, global_thresholds, sample_missing_result_report):
    """Test inspect_reports with a report missing the result field."""
    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()

    await reports_queue.put(sample_missing_result_report)

    with patch("layer_values_monitor.logger.logger"):
        await inspect_reports(reports_queue, disputes_queue, sample_config, max_iterations=1, **global_thresholds)

    # Verify no disputes were generated
    assert disputes_queue.empty()


@pytest.mark.asyncio
async def test_inspect_reports_missing_events(sample_config, global_thresholds, sample_missing_events_report):
    """Test inspect_reports with a report missing the events field."""
    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()

    await reports_queue.put(sample_missing_events_report)

    with patch("builtins.print"):
        await inspect_reports(reports_queue, disputes_queue, sample_config, max_iterations=1, **global_thresholds)

    assert disputes_queue.empty()


@pytest.mark.asyncio
async def test_inspect_reports_malformed(sample_config, global_thresholds, sample_malformed_report):
    """Test inspect_reports with a malformed report that causes an IndexError."""
    # Create queues
    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()

    await reports_queue.put(sample_malformed_report)

    with patch("layer_values_monitor.logger.logger.warning") as mock_logger:
        await inspect_reports(reports_queue, disputes_queue, sample_config, max_iterations=1, **global_thresholds)

    mock_logger.assert_called_once_with("malformed report returned by websocker: list index out of range")

    assert disputes_queue.empty()


@pytest.mark.asyncio
async def test_inspect_reports_no_custom_config_no_metrics(sample_config, global_thresholds, sample_valid_report):
    """Test inspect_reports when no custom config exists and get_metric returns None."""
    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()

    report_data = json.loads(sample_valid_report)
    report_data["result"]["events"]["new_report.query_id"] = ["unknown_query"]
    modified_report = json.dumps(report_data)

    await reports_queue.put(modified_report)

    with (
        patch("layer_values_monitor.monitor.get_metric") as mock_get_metric,
        patch("layer_values_monitor.logger.logger.error") as mock_logger,
    ):
        mock_get_metric.return_value = None

        await inspect_reports(reports_queue, disputes_queue, sample_config, max_iterations=1, **global_thresholds)

        mock_get_metric.assert_called_once()
        mock_logger.assert_called_once_with("no custom configuration and no global thresholds set so can't check value")

        assert disputes_queue.empty()


@pytest.mark.asyncio
async def test_inspect_reports_trusted_value_none(sample_config, global_thresholds, sample_valid_report):
    """Test inspect_reports when trusted value cannot be fetched."""
    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()

    await reports_queue.put(sample_valid_report)

    with (
        patch("layer_values_monitor.monitor.get_metric") as mock_get_metric,
        patch("layer_values_monitor.monitor.get_query_from_data") as mock_get_query,
        patch("layer_values_monitor.monitor.query_catalog.find") as mock_find,
        patch("layer_values_monitor.monitor.get_feed_from_catalog") as mock_get_feed,
        patch("layer_values_monitor.logger.logger.warning") as mock_logger,
    ):
        mock_query = MagicMock()
        mock_query.value_type.decode.return_value = 105.0
        mock_get_query.return_value = mock_query

        mock_find.return_value = [MagicMock(tag="tag1")]

        mock_feed = MagicMock()
        mock_source = AsyncMock()
        # Set trusted value to None to simulate API failure
        mock_source.fetch_new_datapoint.return_value = (None, None)
        mock_feed.source = mock_source
        mock_get_feed.return_value = mock_feed

        mock_get_metric.return_value = Metrics(
            metric="percentage", alert_threshold=0.1, warning_threshold=0.2, minor_threshold=0.3, major_threshold=0.4
        )

        await inspect_reports(reports_queue, disputes_queue, sample_config, max_iterations=1, **global_thresholds)

        mock_logger.assert_called_once_with(
            "can't compare values; unable to fetch trusted value from api, query type: percentage"
        )

        assert disputes_queue.empty()


@pytest.mark.asyncio
async def test_inspect_reports(
    mock_websockets_connect, test_report_messages, mock_websocket, event_queue, disputes_queue, config_watcher
):
    uri = "ws://test-server.com/ws"

    message_index = 0

    async def mock_recv():
        nonlocal message_index
        if message_index < len(test_report_messages):
            message = test_report_messages[message_index]
            message_index += 1
            return message
        else:
            raise websockets.ConnectionClosed(None, None)

    mock_websocket.recv.side_effect = mock_recv

    listener_task = asyncio.create_task(listen_to_new_report_events(uri, event_queue))
    config = {
        "83a7f3d48786ac2667503a61e8c415438ed2922eb86a2906e4ee66d9a2ce4992": {
            "metric": "percentage",
            "alert_threshold": 0.5,
            "warning_threshold": 0.75,
            "minor_threshold": 0.5,
            "major_threshold": 0.25,
        }
    }
    config_watcher.config = config
    with (
        patch("layer_values_monitor.monitor.get_feed_from_catalog") as mock_get_feed,
        patch("layer_values_monitor.monitor.generic_alert") as mock_generate_msg,
    ):
        mock_feed = MagicMock()
        mock_source = AsyncMock()
        mock_source.fetch_new_datapoint.return_value = (350.0, None)
        mock_feed.source = mock_source
        mock_get_feed.return_value = mock_feed
        await inspect_reports(event_queue, disputes_queue, config_watcher, len(test_report_messages))
        assert not disputes_queue.empty()
        mock_generate_msg.assert_called()
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass
