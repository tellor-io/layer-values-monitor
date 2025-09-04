"""Catchup logic for processing missed blocks."""

import asyncio
import logging
from typing import Any

import aiohttp


class HeightTracker:
    """Track the last processed block height to detect missed blocks."""

    def __init__(self, max_catchup_blocks: int = 15) -> None:
        """Initialize the height tracker with starting height of 0."""
        self.last_height = 0
        self.max_catchup_blocks = max_catchup_blocks

    def update(self, height: int) -> None:
        """Update the last processed height."""
        if height > self.last_height:
            self.last_height = height

    def get_missed_range(self, current_height: int) -> tuple[int, int] | None:
        """Get the range of missed blocks, if any, limited to max_catchup_blocks."""
        if current_height > self.last_height + 1:
            start_height = self.last_height + 1
            end_height = current_height - 1

            # Limit catch-up to max_catchup_blocks
            if end_height - start_height + 1 > self.max_catchup_blocks:
                start_height = max(start_height, current_height - self.max_catchup_blocks)
                return (start_height, end_height)

            return (start_height, end_height)
        return None


async def get_current_height(uri: str) -> int | None:
    """Get the current blockchain height via RPC."""
    rpc_url = f"http://{uri}"
    payload = {"jsonrpc": "2.0", "method": "status", "params": {}, "id": 1}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rpc_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return int(data["result"]["sync_info"]["latest_block_height"])
    except Exception:
        return None
    return None


async def query_block_events(uri: str, height: int) -> dict[str, Any] | None:
    """Query block events for a specific height via RPC."""
    rpc_url = f"http://{uri}"
    payload = {"jsonrpc": "2.0", "method": "block_results", "params": {"height": str(height)}, "id": 1}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rpc_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("result")
    except Exception:
        return None
    return None


async def process_missed_blocks(
    uri: str, start_height: int, end_height: int, raw_data_q: asyncio.Queue, logger: logging.Logger
) -> None:
    """Process missed blocks and inject events into the raw data queue."""
    logger.info(f"🔄 Processing missed blocks {start_height}-{end_height}")

    for height in range(start_height, end_height + 1):
        block_events = await query_block_events(uri, height)
        if not block_events:
            continue

        # Process both begin_block_events and end_block_events
        all_events = block_events.get("begin_block_events", []) + block_events.get("end_block_events", [])

        for event in all_events:
            # Convert event to WebSocket format for processing
            if event.get("type") in ["new_report", "aggregate_report"]:
                # Build attributes dict
                attributes = {attr["key"]: [attr["value"]] for attr in event.get("attributes", [])}
                attributes["tx.height"] = [str(height)]

                ws_format = {"result": {"events": attributes, "data": {"type": "tendermint/event/NewBlockEvents"}}}
                await raw_data_q.put(ws_format)

    logger.info(f"✅ Completed processing missed blocks {start_height}-{end_height}")
