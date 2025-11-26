"""Catchup logic for processing missed blocks."""

import asyncio
import json
import logging
from typing import Any

import aiohttp


class HeightTracker:
    """Track the last processed block height to detect missed blocks."""

    def __init__(self, max_catchup_blocks: int = 15) -> None:
        """Initialize height tracker at height 0."""
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


async def get_current_height(uri: str, session: aiohttp.ClientSession | None = None) -> int | None:
    """Get Layer chain height via RPC."""
    rpc_url = f"http://{uri}"
    payload = {"jsonrpc": "2.0", "method": "status", "params": {}, "id": 1}

    async def _query(sess: aiohttp.ClientSession) -> int | None:
        try:
            async with sess.post(rpc_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return int(data["result"]["sync_info"]["latest_block_height"])
        except Exception:
            return None
        return None

    if session:
        return await _query(session)
    else:
        async with aiohttp.ClientSession() as sess:
            return await _query(sess)


async def query_block_events(
    uri: str, height: int, logger: logging.Logger, session: aiohttp.ClientSession | None = None
) -> dict[str, Any] | None:
    """Query block events for a specific height via RPC with fallback to curl."""
    rpc_url = f"http://{uri}"
    payload = {"jsonrpc": "2.0", "method": "block_results", "params": {"height": str(height)}, "id": 1}

    async def _query_with_session(sess: aiohttp.ClientSession) -> dict[str, Any] | None:
        try:
            async with sess.post(rpc_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("result")
        except Exception as e:
            logger.warning(f"aiohttp failed for height {height}: {e}, trying curl fallback")
        return None

    # Try aiohttp first
    if session:
        result = await _query_with_session(session)
        if result:
            return result
    else:
        async with aiohttp.ClientSession() as sess:
            result = await _query_with_session(sess)
            if result:
                return result

    # Fallback to curl command (async)
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps(payload),
            rpc_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

        if proc.returncode == 0:
            data = json.loads(stdout.decode())
            return data.get("result")
        else:
            logger.warning(f"curl failed for height {height}: {stderr.decode()}")
    except TimeoutError:
        logger.warning(f"curl timeout for height {height}")
        if proc:
            proc.kill()
            await proc.wait()
    except Exception as e:
        logger.warning(f"curl fallback failed for height {height}: {e}")

    return None


async def process_missed_blocks(
    uri: str, start_height: int, end_height: int, raw_data_q: asyncio.Queue, logger: logging.Logger
) -> None:
    """Process missed blocks by extracting all new_report events first, then processing chronologically."""
    logger.info(f"🔄 Processing missed blocks {start_height}-{end_height}")

    # Create a single session for all block queries
    async with aiohttp.ClientSession() as session:
        # Get all new_report events from missed blocks
        all_new_reports = []
        for height in range(start_height, end_height + 1):
            block_events = await query_block_events(uri, height, logger, session)
            if not block_events:
                continue

            txs_results = block_events.get("txs_results", [])

            for tx_index, tx_result in enumerate(txs_results):
                tx_events = tx_result.get("events", [])
                for event in tx_events:
                    if event.get("type") == "new_report":
                        attributes = {}
                        for attr in event.get("attributes", []):
                            key = attr["key"]
                            value = attr["value"]
                            attributes[key] = [value]

                        attributes["tx.height"] = [str(height)]

                        if "tx.hash" not in attributes:
                            pass

                        all_new_reports.append(
                            {"height": height, "tx_index": tx_index, "attributes": attributes, "event": event}
                        )

        # Sort all events chronologically by height, then by tx_index within same block
        all_new_reports.sort(key=lambda x: (x["height"], x["tx_index"]))

        # Process events in batches chronologically
        BATCH_SIZE = 10  # Process events in batches of 10
        total_events = len(all_new_reports)

        logger.info(f"📊 Extracted {total_events} new_report events from {end_height - start_height + 1} blocks")

        if total_events == 0:
            logger.info("ℹ️ No new_report events found in missed blocks - nothing to process")
            return

        # log events per block
        events_by_height = {}
        for event in all_new_reports:
            height = event["height"]
            if height not in events_by_height:
                events_by_height[height] = 0
            events_by_height[height] += 1

        for height in sorted(events_by_height.keys()):
            count = events_by_height[height]
            logger.info(f"  📦 Block {height}: {count} new_report event{'s' if count > 1 else ''}")

        for i in range(0, total_events, BATCH_SIZE):
            batch = all_new_reports[i : i + BATCH_SIZE]
            batch_heights = [event["height"] for event in batch]

            logger.info(
                f"🔄 Processing batch {i // BATCH_SIZE + 1}: heights {min(batch_heights)}-"
                f"{max(batch_heights)} ({len(batch)} events)"
            )

            # process each event in the batch
            for event_data in batch:
                ws_format = {"result": {"events": event_data["attributes"], "data": {"type": "tendermint/event/NewBlockEvents"}}}
                await raw_data_q.put(ws_format)

            # small delay between batches
            if i + BATCH_SIZE < total_events:
                await asyncio.sleep(0.1)

        logger.info(f"✅ Completed processing {total_events} new_report events from blocks {start_height}-{end_height}")
