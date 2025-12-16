import asyncio
import logging
from unittest.mock import MagicMock

from layer_values_monitor.catchup import HeightTracker
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
    """Test the basic flow with proper height isolation.
    
    Each collection should contain only reports from one height.
    """
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()

    # height 100, data1
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

    # height 100, data2
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

    # height 101, data1
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

    # height 102, data3
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

    height_tracker = HeightTracker()
    await raw_data_queue_handler(raw_data_q, new_reports_q, None, mock_logger, height_tracker, max_iterations=6)

    # Should have 3 collections: height 100, height 101, height 102
    assert new_reports_q.qsize() == 3

    # First collection: height 100 with BOTH query_id_1 and query_id_2
    first_collection = await new_reports_q.get()
    assert len(first_collection) == 2, "height 100 should have 2 query IDs"
    assert "query_id_1" in first_collection
    assert "query_id_2" in first_collection
    
    # Verify both reports are from height 100
    assert first_collection["query_id_1"][0].value == "0x123"
    assert first_collection["query_id_2"][0].value == "0x456"

    # Second collection: height 101 with only query_id_1
    second_collection = await new_reports_q.get()
    assert len(second_collection) == 1, "height 101 should have 1 query ID"
    assert "query_id_1" in second_collection
    assert "query_id_2" not in second_collection, "query_id_2 should NOT be in height 101 collection"
    
    # Verify report is from height 101
    assert second_collection["query_id_1"][0].value == "0x789"
    assert second_collection["query_id_1"][0].reporter == "reporter3"

    # Third collection: height 102 with only query_id_3
    third_collection = await new_reports_q.get()
    assert len(third_collection) == 1, "Height 102 should have 1 query ID"
    assert "query_id_3" in third_collection
    assert third_collection["query_id_3"][0].query_id == "query_id_3"


@pytest.mark.asyncio
async def test_raw_data_queue_handler_empty_queue(mock_logger):
    """Test handling of an empty queue."""
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()

    # Create and run the task with a short timeout
    height_tracker = HeightTracker()
    task = asyncio.create_task(
        raw_data_queue_handler(raw_data_q, new_reports_q, None, mock_logger, height_tracker, max_iterations=1)
    )

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
    """Test handling multiple reports with the same block height.
    
    Multiple reports at the same height should be batched together.
    When height changes, the batch should be processed without mixing heights.
    """
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()

    height_tracker = HeightTracker()
    
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
    
    # Add a trigger report at height 202 to ensure height 201 gets processed
    trigger_report = {
        "result": {
            "events": {
                "tx.height": ["202"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x..."],
                "new_report.query_id": ["trigger_query_id"],
                "new_report.value": ["0xtrigger"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["4000"],
                "new_report.reporter": ["reporter4"],
                "new_report.timestamp": ["1625097600000"],
                "new_report.meta_id": ["meta"],
                "tx.hash": ["hash4"],
            }
        }
    }
    await raw_data_q.put(trigger_report)

    # Process all reports (4 reports = 4 iterations)
    await raw_data_queue_handler(raw_data_q, new_reports_q, None, mock_logger, height_tracker, max_iterations=4)

    # Should have 3 collections: height 200, height 201, height 202
    assert new_reports_q.qsize() == 3

    # Get first collection - should have both reports from height 200
    first_collection = await new_reports_q.get()
    assert "same_query_id" in first_collection
    # First collection has both reports from same height
    assert len(first_collection["same_query_id"]) == 2
    assert first_collection["same_query_id"][0].value == "0x111"
    assert first_collection["same_query_id"][1].value == "0x222"

    # Get second collection - should have report from height 201 ONLY
    second_collection = await new_reports_q.get()
    assert "other_query_id" in second_collection
    assert "same_query_id" not in second_collection, "Height 201 should not contain height 200 reports"
    assert len(second_collection["other_query_id"]) == 1
    assert second_collection["other_query_id"][0].value == "0xfinal"
    
    # Get third collection - should have report from height 202
    third_collection = await new_reports_q.get()
    assert "trigger_query_id" in third_collection
    assert len(third_collection["trigger_query_id"]) == 1


@pytest.mark.asyncio
async def test_raw_data_queue_handler():
    """Test the raw_data_queue_handler function processes reports with height isolation.
    
    Reports from different heights should NOT be mixed in the same collection.
    """

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

    height_tracker = HeightTracker()
    await raw_data_queue_handler(raw_data_q, new_reports_q, None, logger, height_tracker, max_iterations=3)

    assert not new_reports_q.empty(), "Queue should have items"

    # Should have 2 collections: height 5, height 6
    assert new_reports_q.qsize() == 2

    # First collection: height 5 with BOTH query1 and query2
    first_collection = await new_reports_q.get()
    assert len(first_collection) == 2, "Height 5 should have 2 query IDs"
    assert "query1" in first_collection, "Should have query1"
    assert "query2" in first_collection, "Should have query2"
    
    # Verify both reports are from height 5
    assert first_collection["query1"][0].value == "50000", "query1 should have value 50000"
    assert first_collection["query2"][0].value == "3000", "query2 should have value 3000"

    # Second collection: height 6 with only query1
    second_collection = await new_reports_q.get()
    assert len(second_collection) == 1, "Height 6 should have 1 query ID"
    assert "query1" in second_collection, "Should have query1"
    assert "query2" not in second_collection, "Should NOT have query2 from height 5"
    
    # Verify query1 from height 6
    assert second_collection["query1"][0].value == "52000", "query1 from height 6 should have value 52000"


@pytest.mark.asyncio
async def test_new_report_followed_by_aggregate_same_height(mock_logger):
    """Test that new reports are processed when aggregate arrives at same height.

    This tests the critical fix for the single-reporter testnet scenario where
    a bad report is followed immediately by an aggregate report at the same height.
    The new report must be flushed and processed for disputes before the aggregate.
    """
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()
    agg_reports_q = asyncio.Queue()

    # New report at height 100
    new_report_data = {
        "result": {
            "events": {
                "tx.height": ["100"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x123"],
                "new_report.query_id": ["83a7f3d48786ac26"],
                "new_report.value": ["0x125690000"],  # Bad value that should be disputed
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["1000000"],
                "new_report.reporter": ["reporter1"],
                "new_report.timestamp": ["1625097600000"],
                "new_report.meta_id": ["57"],
                "tx.hash": ["hash1"],
            }
        }
    }

    # Aggregate report at the same height 100 - this triggers the EndBlock processing
    aggregate_report_data = {
        "result": {
            "events": {
                "tx.height": ["100"],
                "aggregate_report.query_id": ["83a7f3d48786ac26"],
                "aggregate_report.query_data": ["0x123"],
                "aggregate_report.value": ["0x125690000"],
                "aggregate_report.aggregate_power": ["1000000"],
                "aggregate_report.micro_report_height": ["116"],
            }
        }
    }

    await raw_data_q.put(new_report_data)
    await raw_data_q.put(aggregate_report_data)

    # Process the events - this should process both the new report and aggregate
    height_tracker = HeightTracker()
    await raw_data_queue_handler(raw_data_q, new_reports_q, agg_reports_q, mock_logger, height_tracker, max_iterations=2)

    # Verify the new report was processed (sent to new_reports_q for dispute checking)
    assert not new_reports_q.empty(), "New reports queue should contain the flushed report"
    new_reports = await new_reports_q.get()
    assert "83a7f3d48786ac26" in new_reports, "Should contain the bad report for dispute processing"
    assert len(new_reports["83a7f3d48786ac26"]) == 1, "Should have exactly one report"
    assert new_reports["83a7f3d48786ac26"][0].meta_id == "57", "Should be the correct report"

    # Verify the aggregate report was also processed
    assert not agg_reports_q.empty(), "Aggregate reports queue should contain the aggregate report"
    agg_report = await agg_reports_q.get()
    assert agg_report.query_id == "83a7f3d48786ac26", "Should be the same query ID"
    assert agg_report.micro_report_height == "116", "Should have correct micro report height"

    # Verify event detection was logged
    detection_calls = [str(call) for call in mock_logger.info.call_args_list if "Detected new_report event" in str(call)]
    assert len(detection_calls) > 0, f"Should have logged event detection. Actual calls: {mock_logger.info.call_args_list}"


@pytest.mark.asyncio
async def test_two_block_reporting_windows(mock_logger):
    """Test oracle's 2-block reporting window behavior.
    
    Simulates oracle blockchain where:
    - Blocks 100-101: eth/usd window (8 reporters)
    - Blocks 102-103: btc/usd window (8 reporters)  
    - Blocks 104-105: trb/usd window (8 reporters)
    
    Each window should be processed separately without cross-contamination.
    """
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()
    height_tracker = HeightTracker()

    # Helper to create report
    def create_report(height: int, query_id: str, query_type: str, reporter_num: int):
        return {
            "result": {
                "events": {
                    "tx.height": [str(height)],
                    "new_report.query_type": [query_type],
                    "new_report.query_data": ["0x..."],
                    "new_report.query_id": [query_id],
                    "new_report.value": [f"0x{reporter_num:03d}"],
                    "new_report.aggregate_method": ["median"],
                    "new_report.cyclelist": ["cycle1"],
                    "new_report.reporter_power": ["1000"],
                    "new_report.reporter": [f"reporter{reporter_num}"],
                    "new_report.timestamp": ["1625097600000"],
                    "new_report.meta_id": ["meta"],
                    "tx.hash": [f"hash{height}_{reporter_num}"],
                }
            }
        }

    # ETH/USD window: blocks 100-101
    for height in [100, 101]:
        for i in range(1, 9):  # 8 reporters
            await raw_data_q.put(create_report(height, "eth_query_id", "SpotPrice", i))

    # BTC/USD window: blocks 102-103
    for height in [102, 103]:
        for i in range(1, 9):  # 8 reporters
            await raw_data_q.put(create_report(height, "btc_query_id", "SpotPrice", i))

    # TRB/USD window: blocks 104-105
    for height in [104, 105]:
        for i in range(1, 9):  # 8 reporters
            await raw_data_q.put(create_report(height, "trb_query_id", "SpotPrice", i))

    # Process all reports
    await raw_data_queue_handler(
        raw_data_q, new_reports_q, None, mock_logger, height_tracker, 
        max_iterations=48  # 3 windows * 2 blocks * 8 reporters
    )

    # Should have 6 collections (one per block height: 100, 101, 102, 103, 104, 105)
    assert new_reports_q.qsize() == 6, f"Expected 6 collections, got {new_reports_q.qsize()}"

    # Height 100: eth/usd only
    collection_100 = await new_reports_q.get()
    assert len(collection_100) == 1, "Height 100 should have 1 query ID"
    assert "eth_query_id" in collection_100
    assert "btc_query_id" not in collection_100
    assert "trb_query_id" not in collection_100
    assert len(collection_100["eth_query_id"]) == 8, "Height 100 should have 8 eth reports"

    # Height 101: eth/usd only
    collection_101 = await new_reports_q.get()
    assert len(collection_101) == 1, "Height 101 should have 1 query ID"
    assert "eth_query_id" in collection_101
    assert "btc_query_id" not in collection_101
    assert "trb_query_id" not in collection_101
    assert len(collection_101["eth_query_id"]) == 8, "Height 101 should have 8 eth reports"

    # Height 102: btc/usd only
    collection_102 = await new_reports_q.get()
    assert len(collection_102) == 1, "Height 102 should have 1 query ID"
    assert "btc_query_id" in collection_102
    assert "eth_query_id" not in collection_102
    assert "trb_query_id" not in collection_102
    assert len(collection_102["btc_query_id"]) == 8, "Height 102 should have 8 btc reports"

    # Height 103: btc/usd only
    collection_103 = await new_reports_q.get()
    assert len(collection_103) == 1, "Height 103 should have 1 query ID"
    assert "btc_query_id" in collection_103
    assert "eth_query_id" not in collection_103
    assert "trb_query_id" not in collection_103
    assert len(collection_103["btc_query_id"]) == 8, "Height 103 should have 8 btc reports"

    # Height 104: trb/usd only
    collection_104 = await new_reports_q.get()
    assert len(collection_104) == 1, "Height 104 should have 1 query ID"
    assert "trb_query_id" in collection_104
    assert "eth_query_id" not in collection_104
    assert "btc_query_id" not in collection_104
    assert len(collection_104["trb_query_id"]) == 8, "Height 104 should have 8 trb reports"

    # Height 105: trb/usd only
    collection_105 = await new_reports_q.get()
    assert len(collection_105) == 1, "Height 105 should have 1 query ID"
    assert "trb_query_id" in collection_105
    assert "eth_query_id" not in collection_105
    assert "btc_query_id" not in collection_105
    assert len(collection_105["trb_query_id"]) == 8, "Height 105 should have 8 trb reports"
