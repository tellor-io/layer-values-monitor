import asyncio
import logging
from unittest.mock import MagicMock

from layer_values_monitor.custom_types import NewReport
from layer_values_monitor.monitor import raw_data_queue_handler

import pytest


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    logger = MagicMock()
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.debug = MagicMock()
    return logger


@pytest.mark.asyncio
async def test_raw_data_queue_handler_basic_flow(mock_logger):
    """Test the basic flow of the raw_data_queue_handler function."""
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()

    # Create sample raw data with different block heights
    sample_data_1 = {
        "result": {
            "events": {
                "tx.height": ["100"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["query_id_1"],
                "new_report.value": ["0x123"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["1000"],
                "new_report.reporter": ["reporter1"],
                "new_report.timestamp": ["1625097600000"],
                "new_report.meta_id": ["meta1"],
                "tx.hash": ["hash1"],
            }
        }
    }

    # Same block height, different query_id
    sample_data_2 = {
        "result": {
            "events": {
                "tx.height": ["100"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["query_id_2"],
                "new_report.value": ["0x456"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["2000"],
                "new_report.reporter": ["reporter2"],
                "new_report.timestamp": ["1625097600001"],
                "new_report.meta_id": ["meta2"],
                "tx.hash": ["hash2"],
            }
        }
    }

    # Higher block height
    sample_data_3 = {
        "result": {
            "events": {
                "tx.height": ["101"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["query_id_1"],
                "new_report.value": ["0x789"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle2"],
                "new_report.reporter_power": ["3000"],
                "new_report.reporter": ["reporter3"],
                "new_report.timestamp": ["1625097600002"],
                "new_report.meta_id": ["meta3"],
                "tx.hash": ["hash3"],
            }
        }
    }

    sample_data_4 = {
        "result": {
            "events": {
                "tx.height": ["102"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["query_id_3"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.value": ["0x789"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle2"],
                "new_report.reporter_power": ["3000"],
                "new_report.reporter": ["reporter3"],
                "new_report.timestamp": ["1625097600002"],
                "new_report.meta_id": ["meta3"],
                "tx.hash": ["hash3"],
            }
        }
    }

    sample_data_5 = {"result": None}
    sample_data_6 = {"result": {"no_events": True}}

    for data in [sample_data_1, sample_data_2, sample_data_3, sample_data_4, sample_data_5, sample_data_6]:
        await raw_data_q.put(data)

    await raw_data_queue_handler(raw_data_q, new_reports_q, mock_logger, max_iterations=6)

    assert new_reports_q.qsize() == 2

    # Get first collection (block height 100)
    first_collection = await new_reports_q.get()

    # The first collection should have 2 query_ids
    assert len(first_collection) == 2
    assert "query_id_1" in first_collection
    assert "query_id_2" in first_collection
    assert isinstance(first_collection["query_id_1"][0], NewReport)
    assert first_collection["query_id_1"][0].query_id == "query_id_1"
    assert first_collection["query_id_1"][0].value == "0x123"
    assert first_collection["query_id_1"][0].reporter == "reporter1"

    # Check the second report in the first collection
    assert isinstance(first_collection["query_id_2"][0], NewReport)
    assert first_collection["query_id_2"][0].query_id == "query_id_2"
    assert first_collection["query_id_2"][0].value == "0x456"
    assert first_collection["query_id_2"][0].reporter == "reporter2"

    # Get second collection (block height 101)
    second_collection = await new_reports_q.get()

    assert len(second_collection) == 1
    assert "query_id_1" in second_collection

    # Check the report in the second collection
    assert isinstance(second_collection["query_id_1"][0], NewReport)
    assert second_collection["query_id_1"][0].query_id == "query_id_1"
    assert second_collection["query_id_1"][0].value == "0x789"
    assert second_collection["query_id_1"][0].reporter == "reporter3"


@pytest.mark.asyncio
async def test_raw_data_queue_handler_empty_queue(mock_logger):
    """Test handling of an empty queue."""
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()

    # Create and run the task with a short timeout
    task = asyncio.create_task(raw_data_queue_handler(raw_data_q, new_reports_q, mock_logger, max_iterations=1))

    await raw_data_q.put({})

    await asyncio.sleep(0.1)

    assert new_reports_q.qsize() == 0

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_raw_data_queue_handler_sequential_same_height(mock_logger):
    """Test handling multiple reports with the same block height."""
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()

    task = asyncio.create_task(raw_data_queue_handler(raw_data_q, new_reports_q, mock_logger, max_iterations=5))

    # Wait for the task to start
    await asyncio.sleep(0.1)

    # Add a single report with block height 200
    report1 = {
        "result": {
            "events": {
                "tx.height": ["200"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["same_query_id"],
                "new_report.value": ["0x111"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["1000"],
                "new_report.reporter": ["reporter1"],
                "new_report.timestamp": ["1625097600000"],
                "new_report.meta_id": ["meta"],
                "tx.hash": ["hash1"],
            }
        }
    }
    await raw_data_q.put(report1)

    # Add a second report with the same block height
    report2 = {
        "result": {
            "events": {
                "tx.height": ["200"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["same_query_id"],
                "new_report.value": ["0x222"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["2000"],
                "new_report.reporter": ["reporter2"],
                "new_report.timestamp": ["1625097600000"],
                "new_report.meta_id": ["meta"],
                "tx.hash": ["hash2"],
            }
        }
    }
    await raw_data_q.put(report2)

    # Now add a report with a higher block height to trigger collection clearing
    final_report = {
        "result": {
            "events": {
                "tx.height": ["201"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["other_query_id"],
                "new_report.value": ["0xfinal"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["3000"],
                "new_report.reporter": ["reporter3"],
                "new_report.timestamp": ["1625097600000"],
                "new_report.meta_id": ["meta"],
                "tx.hash": ["hash3"],
            }
        }
    }
    await raw_data_q.put(final_report)

    # Wait for the collection to be processed
    await asyncio.sleep(0.5)

    # Now there should be a collection in new_reports_q
    assert new_reports_q.qsize() >= 1

    # Get the collection
    collection = await new_reports_q.get()

    assert "same_query_id" in collection

    # It should have exactly 2 reports
    assert len(collection["same_query_id"]) == 2

    report_values = [report.value for report in collection["same_query_id"]]
    assert "0x111" in report_values
    assert "0x222" in report_values

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_raw_data_queue_handler():
    """Test the raw_data_queue_handler function processes reports correctly."""

    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()
    logger = MagicMock(spec=logging.Logger)

    raw_data_height_5 = {
        "result": {
            "events": {
                "tx.height": ["5"],
                "new_report.query_type": ["price"],
                "new_report.query_data": ["BTC/USD"],
                "new_report.query_id": ["query1"],
                "new_report.value": ["50000"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["12"],
                "new_report.reporter_power": ["100"],
                "new_report.reporter": ["reporter1"],
                "new_report.timestamp": ["1620000000"],
                "new_report.meta_id": ["meta1"],
                "tx.hash": ["hash1"],
            }
        }
    }

    raw_data_height_5_query2 = {
        "result": {
            "events": {
                "tx.height": ["5"],
                "new_report.query_type": ["price"],
                "new_report.query_data": ["ETH/USD"],
                "new_report.query_id": ["query2"],
                "new_report.value": ["3000"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["12"],
                "new_report.reporter_power": ["100"],
                "new_report.reporter": ["reporter1"],
                "new_report.timestamp": ["1620000000"],
                "new_report.meta_id": ["meta2"],
                "tx.hash": ["hash2"],
            }
        }
    }

    raw_data_height_6 = {
        "result": {
            "events": {
                "tx.height": ["6"],
                "new_report.query_type": ["price"],
                "new_report.query_data": ["BTC/USD"],
                "new_report.query_id": ["query1"],
                "new_report.value": ["52000"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["12"],
                "new_report.reporter_power": ["300"],
                "new_report.reporter": ["reporter3"],
                "new_report.timestamp": ["1620000020"],
                "new_report.meta_id": ["meta4"],
                "tx.hash": ["hash4"],
            }
        }
    }

    await raw_data_q.put(raw_data_height_5)
    await raw_data_q.put(raw_data_height_5_query2)
    await raw_data_q.put(raw_data_height_6)

    await raw_data_queue_handler(raw_data_q, new_reports_q, logger, max_iterations=3)

    assert not new_reports_q.empty(), "Queue should have items"
    height_5_reports = await new_reports_q.get()

    assert len(height_5_reports) == 2, "Should have reports for 2 query IDs"
    assert "query1" in height_5_reports, "Should have reports for query1"
    assert "query2" in height_5_reports, "Should have reports for query2"

    # Verify query1 for height 5
    query1_reports = height_5_reports["query1"]
    assert len(query1_reports) == 1, "query1 should have 1 report"
    assert query1_reports[0].value == "50000", "Report should have value 50000"

    # Verify query2 for height 5
    query2_reports = height_5_reports["query2"]
    assert len(query2_reports) == 1, "query2 should have 1 report"
    assert query2_reports[0].value == "3000", "Report should have value 3000"
