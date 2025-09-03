#!/usr/bin/env python3
"""
Test that just prints out the logs for a new_report event.
Adjust the logger.infos in monitor.py raw_data_queue_handler() as desired
uv run pytest tests/test_multi_query_logging.py::test_multi_query_logging -v -s
"""

import asyncio
import logging

from layer_values_monitor.monitor import HeightTracker, raw_data_queue_handler

import pytest


@pytest.mark.asyncio
async def test_multi_query_logging():
    """Demo test showing logging for multiple queries at same height."""
    raw_data_q = asyncio.Queue()
    new_reports_q = asyncio.Queue()

    # Create real logger with console output
    logger = logging.getLogger("test_multi_query")
    logger.setLevel(logging.INFO)

    # Create console handler if not already present
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Create 3 different query IDs with multiple reports each at height 500
    queries = [
        ("a6f013ee23680482", "meta001"),  # BTC/USD - 3 reports
        ("a6f013ee23680482", "meta002"),
        ("a6f013ee23680482", "meta003"),
        ("5c13cd9c97dbb98f", "meta004"),  # ETH/USD - 2 reports
        ("5c13cd9c97dbb98f", "meta005"),
        ("83a7f3d48786ac26", "meta006"),  # Other query - 1 report
    ]

    # Add reports for height 500
    for i, (query_id, meta_id) in enumerate(queries):
        report_data = {
            "result": {
                "events": {
                    "tx.height": ["500"],
                    "new_report.query_type": ["SpotPrice"],
                    "new_report.query_data": ["0x123"],
                    "new_report.query_id": [query_id],
                    "new_report.value": [f"0x{1000 + i}"],
                    "new_report.aggregate_method": ["median"],
                    "new_report.cyclelist": ["cycle1"],
                    "new_report.reporter_power": ["1000"],
                    "new_report.reporter": [f"reporter{i}"],
                    "new_report.timestamp": ["1625097600000"],
                    "new_report.meta_id": [meta_id],
                    "tx.hash": [f"hash{i}"],
                }
            }
        }
        await raw_data_q.put(report_data)

    # Add one report at height 501 to trigger processing of height 500
    trigger_data = {
        "result": {
            "events": {
                "tx.height": ["501"],
                "new_report.query_type": ["SpotPrice"],
                "new_report.query_data": ["0x123"],
                "new_report.query_id": ["trigger_query"],
                "new_report.value": ["0x9999"],
                "new_report.aggregate_method": ["median"],
                "new_report.cyclelist": ["cycle1"],
                "new_report.reporter_power": ["1000"],
                "new_report.reporter": ["trigger_reporter"],
                "new_report.timestamp": ["1625097600000"],
                "new_report.meta_id": ["trigger_meta"],
                "tx.hash": ["trigger_hash"],
            }
        }
    }
    await raw_data_q.put(trigger_data)

    height_tracker = HeightTracker()
    await raw_data_queue_handler(raw_data_q, new_reports_q, None, logger, height_tracker, max_iterations=7)


if __name__ == "__main__":
    asyncio.run(test_multi_query_logging())
