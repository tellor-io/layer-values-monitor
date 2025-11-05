"""Values monitor."""

import asyncio
import json
import logging
import os
import random
import time
from typing import Any

from layer_values_monitor.catchup import HeightTracker, get_current_height, process_missed_blocks
from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.constants import DENOM
from layer_values_monitor.custom_types import (
    AggregateReport,
    Metrics,
    Msg,
    NewReport,
    PendingPause,
    PowerThresholds,
    Reporter,
    ReporterQueryResponse,
)
from layer_values_monitor.discord import generic_alert
from layer_values_monitor.dispute import (
    determine_dispute_category,
    determine_dispute_fee,
    is_disputable,
)
from layer_values_monitor.evm_call import get_evm_call_trusted_value, get_web3_connection
from layer_values_monitor.logger import console_logger
from layer_values_monitor.saga_contract import SagaContractManager
from layer_values_monitor.telliot_feeds import fetch_value, get_feed, get_query
from layer_values_monitor.trb_bridge import decode_report_value, get_trb_bridge_trusted_value
from layer_values_monitor.utils import add_to_table, decode_hex_value

import aiohttp
import websockets
from telliot_feeds.datafeed import DataFeed


async def query_reporters(uri: str, logger: logging.Logger) -> ReporterQueryResponse | None:
    """Query all reporters and calculate total non-jailed power.

    Args:
        uri: RPC endpoint URI (e.g., "localhost:26657")
        logger: Logger instance

    Returns:
        ReporterQueryResponse with reporters list and total non-jailed power, or None if query fails

    """
    rpc_url = f"http://{uri}"

    # Query reporters using ABCI query
    payload = {
        "jsonrpc": "2.0",
        "method": "abci_query",
        "params": {"path": "/layer.reporter.Query/Reporters", "data": "", "prove": False},
        "id": 1,
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rpc_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()

                    if "error" in data:
                        logger.error(f"RPC error querying reporters: {data['error']}")
                        return None

                    result = data.get("result")
                    if not result or "response" not in result:
                        logger.error("Invalid response structure when querying reporters")
                        return None

                    # The response.value contains base64 encoded protobuf data
                    # For now, we'll try a different approach using REST API if available
                    logger.debug("Trying alternative approach to query reporters...")
                    return await query_reporters_rest(uri, logger)

    except Exception as e:
        logger.error(f"Failed to query reporters via RPC: {e}")
        return None


async def query_reporters_rest(uri: str, logger: logging.Logger) -> ReporterQueryResponse | None:
    """Query reporters using REST API endpoint.

    Args:
        uri: Base URI (e.g., "localhost:26657")
        logger: Logger instance

    Returns:
        ReporterQueryResponse with reporters list and total non-jailed power, or None if query fails

    """
    # Try common REST API ports
    rest_ports = ["1317", "1316", "26617"]
    base_host = uri.split(":")[0] if ":" in uri else uri

    for port in rest_ports:
        rest_url = f"http://{base_host}:{port}/layer/reporter/reporters"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(rest_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        return parse_reporters_response(data, logger)

        except Exception as e:
            logger.debug(f"Failed to query reporters via REST on port {port}: {e}")
            continue

    logger.error("Failed to query reporters via all available methods")
    return None


def parse_reporters_response(data: dict[str, Any], logger: logging.Logger) -> ReporterQueryResponse | None:
    """Parse the reporters query response and calculate total non-jailed power.

    Args:
        data: Response data from reporters query
        logger: Logger instance

    Returns:
        ReporterQueryResponse with parsed reporters and total power

    """
    try:
        reporters_data = data.get("reporters", [])
        reporters = []
        total_non_jailed_power = 0

        for reporter_data in reporters_data:
            address = reporter_data.get("address", "")
            power = int(reporter_data.get("power", "0"))

            # Check if reporter is jailed
            metadata = reporter_data.get("metadata", {})
            jailed = metadata.get("jailed", False)
            moniker = metadata.get("moniker", "")

            reporter = Reporter(address=address, power=power, jailed=jailed, moniker=moniker)
            reporters.append(reporter)

            # Add to total power if not jailed
            if not jailed:
                total_non_jailed_power += power

        logger.info(f"Queried {len(reporters)} reporters, total non-jailed power: {total_non_jailed_power}")

        return ReporterQueryResponse(reporters=reporters, total_non_jailed_power=total_non_jailed_power)

    except Exception as e:
        logger.error(f"Failed to parse reporters response: {e}")
        return None


async def listen_to_websocket_events(
    uri: str, queries: list[str], q: asyncio.Queue, logger: logging, height_tracker: HeightTracker
) -> None:
    """Connect to a layer websocket and fetch events, adding them to queue for monitoring.

    uri: address to chain (ie localhost:26657)
    queries: list of query strings to subscribe to
    q: queue to store raw response for later processing
    logger: logger instance
    height_tracker: height tracker to detect missed blocks
    """
    logger.info(f"💡 Starting WebSocket connection for {len(queries)} subscriptions...")

    # Prepare subscription messages
    subscription_messages = []
    for i, query_string in enumerate(queries, 1):
        subscription_messages.append(
            json.dumps({"jsonrpc": "2.0", "method": "subscribe", "id": i, "params": {"query": query_string}})
        )

    ws_uri = f"ws://{uri}/websocket"
    retry_count = 0
    base_delay = 1
    max_delay = 60

    while True:
        try:
            logger.info(f"💡 Connecting to WebSocket at {ws_uri}... (Attempt {retry_count + 1})")
            async with websockets.connect(ws_uri) as websocket:
                # Send all subscription messages
                for i, msg in enumerate(subscription_messages):
                    await websocket.send(msg)
                    logger.info(f"✅ Sent subscription {i + 1}: {queries[i]}")

                # Reset retry count on successful connection
                retry_count = 0
                logger.info("✅ WebSocket connection established successfully")
                while True:
                    response = await websocket.recv()
                    parsed_response = json.loads(response)

                    # Log EVERYTHING to see what we're getting
                    logger.info(f"🔵 Raw WebSocket response: {json.dumps(parsed_response)[:500]}")

                    await q.put(parsed_response)

        except websockets.ConnectionClosed as e:
            logger.warning(f"WebSocket connection closed: {e}")
        except websockets.WebSocketException as e:
            logger.error(f"WebSocket error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)

        logger.info("going through the retry phase since connection was closed")

        # Process missed blocks on reconnection
        if retry_count == 0:  # Only on first reconnection attempt
            try:
                # Get current height from RPC
                current_height = await get_current_height(uri)
                if current_height:
                    missed_range = height_tracker.get_missed_range(current_height)
                    if missed_range:
                        start_height, end_height = missed_range
                        total_missed = end_height - start_height + 1

                        # Log if we're limiting catch-up
                        if total_missed > height_tracker.max_catchup_blocks:
                            logger.warning(
                                f"⚠️ CATCHUP LIMITED - {total_missed} blocks missed, "
                                f"processing only last {height_tracker.max_catchup_blocks} blocks "
                                f"({start_height}-{end_height}) to prevent stale price comparisons"
                            )
                        else:
                            logger.info(f"✅ Processing {total_missed} missed blocks ({start_height}-{end_height})")

                        await process_missed_blocks(uri, start_height, end_height, q, logger)
                        height_tracker.update(current_height)
                        logger.info("✅ Catch-up processing completed successfully")
            except Exception as e:
                logger.error(f"Failed to process missed blocks: {e}")

        # Calculate delay with exponential backoff and jitter for reconnection
        delay = min(base_delay * (2**retry_count), max_delay)
        # Add jitter to prevent thundering herd problem
        jitter = random.uniform(0, 0.1 * delay)
        actual_delay = delay + jitter

        retry_count += 1
        logger.info(f"Reconnecting in {actual_delay:.2f} seconds (retry {retry_count})")
        await asyncio.sleep(actual_delay)


async def raw_data_queue_handler(
    raw_data_q: asyncio.Queue,
    new_reports_q: asyncio.Queue,
    agg_reports_q: asyncio.Queue | None,
    logger: logging,
    height_tracker: HeightTracker,
    max_iterations: float = float("inf"),  # use iterations var for testing purposes instead of using a while loop
) -> None:
    """Process raw WebSocket data and route to appropriate queues.

    Handles both new reports and aggregate reports from the same WebSocket stream.
    New reports are collected by height and sent to new_reports_q.
    Aggregate reports are sent directly to agg_reports_q.
    """
    iterations = 0
    reports_collections: dict[str, list[NewReport]] = {}
    # Smart batching configuration
    MAX_BATCH_SIZE = 25  # Process if we hit this many reports
    BATCH_TIMEOUT = 5.0  # Process after 5 seconds regardless
    # current height being collected for - start as None to detect first height
    current_height = None
    last_batch_time = time.time()
    while iterations < max_iterations:
        iterations += 1
        raw_data: dict[str, Any] = await raw_data_q.get()
        raw_data_q.task_done()

        result: dict[str, Any] = raw_data.get("result")

        if result is None:
            continue

        # Skip subscription acknowledgments (empty result)
        if result == {}:
            continue

        # Filter out duplicate events: Tendermint sends the same aggregate reports in both
        # 'NewBlock' and 'NewBlockEvents'. We only process 'NewBlockEvents' to avoid duplicates.
        data = result.get("data", {})
        event_type = data.get("type")
        if event_type == "tendermint/event/NewBlock":
            continue

        events = result.get("events")
        if events is None:
            continue

        # Determine event type by presence of keys
        is_new_report = "new_report.query_id" in events
        is_agg_report = "aggregate_report.query_id" in events or "aggregate_report.aggregate_power" in events

        if is_new_report:
            logger.info(
                f"✅ Detected new_report event with query_id: {events.get('new_report.query_id', ['unknown'])[0][:16]}"
            )
            try:
                # get current height from event
                height = events["tx.height"][0]
                height = int(height)
                report = NewReport(
                    query_type=events["new_report.query_type"][0],
                    query_data=events["new_report.query_data"][0],
                    query_id=events["new_report.query_id"][0],
                    value=events["new_report.value"][0],
                    aggregate_method=events["new_report.aggregate_method"][0],
                    cyclelist=events["new_report.cyclelist"][0],
                    power=events["new_report.reporter_power"][0],
                    reporter=events["new_report.reporter"][0],
                    timestamp=events["new_report.timestamp"][0],
                    meta_id=events["new_report.meta_id"][0],
                    tx_hash=events["tx.hash"][0],
                )

                # Add the current report to the collection for the current height
                reports_collected = reports_collections.get(report.query_id, None)
                if reports_collected is None:
                    reports_collections[report.query_id] = [report]
                else:
                    reports_collections[report.query_id].append(report)

                # Smart batching logic: process reports based on multiple conditions
                should_process = False
                process_reason = ""

                # Height has incremented (process previous height's reports)
                if current_height is not None and height > current_height:
                    should_process = True
                    process_reason = f"height increment ({current_height} -> {height})"

                # Batch size threshold reached
                elif len(reports_collections) >= MAX_BATCH_SIZE:
                    should_process = True
                    process_reason = f"batch size limit ({len(reports_collections)} >= {MAX_BATCH_SIZE})"

                # Timeout reached
                elif time.time() - last_batch_time > BATCH_TIMEOUT:
                    should_process = True
                    process_reason = f"timeout ({time.time() - last_batch_time:.1f}s > {BATCH_TIMEOUT}s)"

                # First report (current_height is None) - process immediately
                elif current_height is None:
                    should_process = True
                    process_reason = "first report"

                if should_process and len(reports_collections) > 0:
                    total_reports = sum(len(reports) for reports in reports_collections.values())
                    query_counts = [f"{query_id[:12]}:{len(reports)}" for query_id, reports in reports_collections.items()]

                    collected_height = current_height if current_height is not None else height
                    logger.info(
                        f"Processing {total_reports} reports collected at height {collected_height} "
                        f"({process_reason}), qIds: [{', '.join(query_counts)}]"
                    )

                    await new_reports_q.put(dict(reports_collections))
                    reports_collections.clear()
                    last_batch_time = time.time()

                # Update current height (either first time or after processing)
                if current_height is None or height > current_height:
                    current_height = height
                    # Track height for missed block detection
                    height_tracker.update(height)

            except (KeyError, IndexError) as e:
                logger.warning(f"malformed new_report returned by websocket: {e.__str__()}")
                continue

        elif is_agg_report and agg_reports_q is not None:
            # This ensures new reports are processed for disputes even when aggregate arrives at same height
            if len(reports_collections) > 0:
                total_reports = sum(len(reports) for reports in reports_collections.values())
                query_counts = [f"{query_id[:12]}:{len(reports)}" for query_id, reports in reports_collections.items()]

                logger.info(
                    f"Processing {total_reports} reports collected at height {height}, qIds: [{', '.join(query_counts)}]"
                )

            try:
                height = current_height

                agg_report = AggregateReport(
                    query_id=events["aggregate_report.query_id"][0],
                    query_data=events["aggregate_report.query_data"][0],
                    value=events["aggregate_report.value"][0],
                    aggregate_power=events["aggregate_report.aggregate_power"][0],
                    micro_report_height=events["aggregate_report.micro_report_height"][0],
                    height=height,
                )

                # Track height for missed block detection
                if height:
                    height_tracker.update(height)

                await agg_reports_q.put(agg_report)
            except (KeyError, IndexError) as e:
                logger.warning(f"malformed aggregate_report returned by websocket: {e.__str__()}")
                continue
        else:
            # Unknown or not interested
            continue

    # Cleanup: Process any remaining reports before function exits
    if len(reports_collections) > 0:
        total_reports = sum(len(reports) for reports in reports_collections.values())
        query_counts = [f"{query_id[:12]}:{len(reports)}" for query_id, reports in reports_collections.items()]

        collected_height = current_height if current_height is not None else "unknown"
        logger.info(
            f"Processing {total_reports} remaining reports collected at height {collected_height} "
            f"(cleanup), qIds: [{', '.join(query_counts)}]"
        )

        await new_reports_q.put(dict(reports_collections))
        reports_collections.clear()


async def inspect_reports(
    reports: list[NewReport],
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher,
    logger: logging,
) -> None:
    """Fetch value for a query id and check it against the list of reports' values and determine if any are disputable.

    reports: list of new_reports for a query id
    disputes_q: the queue to add disputes to for dispute processing
    config_watcher: live config for query ids threshold settings
    """
    if len(reports) == 0:
        return None
    query_data = reports[0].query_data
    query_id = reports[0].query_id
    query_type = reports[0].query_type

    # Check if query type is supported
    if not config_watcher.is_supported_query_type(query_type):
        # Extract asset pair if possible for better logging
        asset_pair = "Unknown"
        try:
            query_obj = get_query(query_data)
            if query_obj and hasattr(query_obj, "asset") and hasattr(query_obj, "currency"):
                asset_pair = f"{query_obj.asset}/{query_obj.currency}"
        except Exception:
            pass

        # Send Discord alert for unknown query type
        await send_unsupported_query_alert(
            query_id,
            query_type,
            asset_pair,
            reports[0],
            logger,
            description=f"⚠️ **QUERY TYPE NOT SUPPORTED ({query_type.upper()})**",
            try_decode=False,
        )
        return None

    # Get metrics configuration using new method
    metrics = config_watcher.get_metrics_for_query(query_id, query_type)
    if metrics is None:
        logger.error(f"Unable to get metrics for query {query_id[:16]}... of type {query_type}")
        return None

    # Branch based on query type - each type has its own inspection path
    logger.info(f"🔀 Routing to {query_type} inspection path...")

    if query_type.lower() == "spotprice":
        return await inspect_spotprice_path(
            reports, disputes_q, config_watcher, query_id, query_data, query_type, metrics, logger
        )
    elif query_type.lower() == "evmcall":
        return await inspect_evmcall_path(reports, disputes_q, query_id, query_data, metrics, logger)
    elif query_type.lower() == "trbbridge":
        return await inspect_trbbridge_path(reports, disputes_q, query_id, metrics, logger)
    else:
        logger.error(f"❌ No inspection path defined for query type: {query_type}")
        return None


# ====================================================================================
# QUERY TYPE SPECIFIC INSPECTION PATHS
# ====================================================================================


async def inspect_spotprice_path(
    reports: list[NewReport],
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher,
    query_id: str,
    query_data: str,
    query_type: str,
    metrics: Metrics,
    logger: logging,
) -> None:
    """SpotPrice inspection path with 4 scenarios.

    1. In config AND in telliot → proceed normally
    2. In telliot but NOT in config → alert + proceed with global defaults
    3. NOT in telliot and NOT in config → alert + skip (foreign query)
    4. In config but NOT in telliot → NEW alert + skip (can't get trusted value).
    """
    logger.debug(f"🔍 SpotPrice inspection starting - QueryID: {query_id[:16]}..., {len(reports)} report(s)")

    # Step 1: Check if query is in our config
    query_type_configs = config_watcher.query_configs.get(query_type.lower(), {})
    has_specific_config = query_id.lower() in query_type_configs
    logger.debug(f" Query in config? {has_specific_config}")

    # Step 2: Check if query is in telliot catalog
    from telliot_feeds.queries.query_catalog import query_catalog

    catalog_entry = query_catalog.find(query_id=query_id)
    in_telliot = len(catalog_entry) > 0
    logger.debug(f"Query in telliot? {in_telliot}")

    # Step 3: Extract asset pair and decode value (for alerts)
    asset_pair = "Unknown"
    decoded_value = reports[0].value
    try:
        query_obj = get_query(query_data)
        if query_obj:
            if hasattr(query_obj, "asset") and hasattr(query_obj, "currency"):
                asset_pair = f"{query_obj.asset}/{query_obj.currency}"
                logger.debug(f"Extracted asset pair: {asset_pair}")
            try:
                decoded_value = query_obj.value_type.decode(bytes.fromhex(reports[0].value))
                logger.debug(f"Decoded value: {decoded_value}")
            except Exception as e:
                logger.debug(f"Failed to decode value: {e}")
    except Exception as e:
        logger.debug(f"Failed to get query object: {e}")

    # Step 4: Handle the 4 scenarios

    # Scenario 3: NOT in config AND NOT in telliot → Foreign query (SKIP)
    if not has_specific_config and not in_telliot:
        logger.info(f"Foreign query - NOT in config AND NOT in telliot (query: {query_id[:16]}..., asset: {asset_pair})")
        description = f"⚠️ **QUERY NOT FOUND IN TELLIOT OR CONFIGS{f' ({asset_pair})' if asset_pair != 'Unknown' else ''}**"
        await send_unsupported_query_alert(
            query_id, query_type, asset_pair, reports[0], logger, description=description, try_decode=True
        )
        return None  # Skip inspection - no trusted value available

    # Scenario 4: IN config but NOT in telliot → NEW ALERT (SKIP - can't get trusted value)
    elif has_specific_config and not in_telliot:
        logger.info(f"Query in config but NOT in telliot (query: {query_id[:16]}..., asset: {asset_pair})")
        alert_msg = f"**QueryId:** {query_id}\n"
        alert_msg += f"**QueryType:** {query_type}\n"
        if asset_pair != "Unknown":
            alert_msg += f"**Asset pair:** {asset_pair}\n"
        alert_msg += f"**Value:** {decoded_value}\n"
        alert_msg += f"**Reporter:** {reports[0].reporter}\n"
        alert_msg += f"**Tx Hash:** {reports[0].tx_hash}\n"
        alert_msg += "**Status:** Cannot inspect - telliot unavailable for trusted value"

        logger.info(f"Config-but-not-telliot alert:\n{alert_msg}")
        generic_alert(alert_msg, description="🆕 **QUERY IN CONFIG, BUT NOT TELLIOT**")
        return None  # Can't get trusted value from telliot

    # Scenario 2: NOT in config but IN telliot → Unconfigured query (PROCEED with global defaults)
    elif not has_specific_config and in_telliot:
        logger.info(
            f"Query in telliot but NOT in config - proceeding with global defaults "
            f"(query: {query_id[:16]}..., asset: {asset_pair})"
        )
        # Check if this query type typically has per-query configs
        has_specific_configs = any(k != "defaults" for k in query_type_configs.keys())

        if has_specific_configs:
            # Log info message (don't send Discord alert - we'll alert on value discrepancy if needed)
            logger.info(
                f"⚠️ Query found in telliot but not in config file - "
                f"QueryId: {query_id}, Asset: {asset_pair}, "
                f"Using global defaults (alert={metrics.alert_threshold}, warning={metrics.warning_threshold})"
            )
        # Fall through to proceed with inspection using global defaults
    else:
        # Scenario 1: IN config AND IN telliot → Normal path (PROCEED)
        logger.info(f"Normal path - query in config AND telliot (query: {query_id[:16]}..., asset: {asset_pair})")

    # Step 5: Proceed with telliot inspection (for scenarios 1 and 2)
    logger.debug(f"Getting query object and feed for {query_id[:16]}...")
    query = get_query(query_data)
    if query is None:
        logger.error("Unable to get query object")
        return None

    feed = await get_feed(query_id, query, logger)
    if feed is None:
        logger.error("Unable to get feed")
        return None

    logger.debug("Fetching trusted value from feed...")
    trusted_value, _ = await fetch_value(feed)
    if trusted_value is None:
        logger.error("Unable to fetch trusted value")
        return None

    logger.debug(f"Trusted value fetched: {trusted_value}")

    # Create fetcher lambda for double-check logic
    async def fetch_trusted_value() -> tuple[Any, Any]:
        return await fetch_value(feed)

    logger.debug(f"Inspecting {len(reports)} report(s)...")
    for r in reports:
        reported_value = query.value_type.decode(bytes.fromhex(r.value))
        logger.debug(f"Report - reporter: {r.reporter}, reported_value: {reported_value}, power: {r.power}")
        await inspect(
            r,
            reported_value,
            trusted_value,
            disputes_q,
            metrics,
            logger,
            query=query,
            trusted_value_fetcher=fetch_trusted_value,
        )

    logger.debug(f"✅ SpotPrice inspection complete for {query_id[:16]}...")
    return None


async def inspect_evmcall_path(
    reports: list[NewReport],
    disputes_q: asyncio.Queue,
    query_id: str,
    query_data: str,
    metrics: Metrics,
    logger: logging,
) -> None:
    """EVMCall inspection path."""
    logger.info(f"⚙️ EVMCall inspection - QueryID: {query_id[:16]}...")

    # Get query object
    query = get_query(query_data)
    if query is None:
        logger.error("Unable to get query object for EVMCall")
        return None

    # Get feed
    feed = await get_feed(query_id, query, logger)
    if feed is None:
        logger.error("Unable to get feed for EVMCall")
        return None

    # Call existing implementation
    return await inspect_evm_call_reports(reports, feed, disputes_q, query_id, metrics, logger)


async def inspect_trbbridge_path(
    reports: list[NewReport],
    disputes_q: asyncio.Queue,
    query_id: str,
    metrics: Metrics,
    logger: logging,
) -> None:
    """TRBBridge inspection path."""
    logger.info(f"🌉 TRBBridge inspection - QueryID: {query_id[:16]}...")
    logger.info(f"🔎 Inspecting {len(reports)} TRBBridge report(s)...")

    # Call existing implementation
    return await inspect_trbbridge_reports(reports, disputes_q, query_id, metrics, logger)


async def new_reports_queue_handler(
    new_reports_q: asyncio.Queue,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher,
    logger: logging,
) -> None:
    """Handle new reports from the queue and process them."""
    running_tasks = set()
    task_cleanup_threshold = 1000  # Safety threshold for task cleanup

    while True:
        new_reports: dict = await new_reports_q.get()

        # Periodic cleanup of completed tasks to prevent memory growth
        if len(running_tasks) > task_cleanup_threshold:
            completed_tasks = {t for t in running_tasks if t.done()}
            running_tasks -= completed_tasks
            logger.warning(f"🧹 Cleaned up {len(completed_tasks)} completed tasks (active: {len(running_tasks)})")

        for report in new_reports.values():
            # Create a task for each query id
            task = asyncio.create_task(inspect_reports(report, disputes_q, config_watcher, logger))

            # Add task tracking and cleanup
            running_tasks.add(task)
            task.add_done_callback(running_tasks.discard)

            # Handle exceptions
            def handle_task_exception(t: asyncio.Task) -> None:
                if t.exception():
                    logger.error(f"Task raised exception: {t.exception()}")

            task.add_done_callback(handle_task_exception)

        new_reports_q.task_done()


async def inspect_aggregate_report(
    agg_report: AggregateReport,
    config_watcher: ConfigWatcher,
    logger: logging,
    uri: str | None = None,
    power_thresholds: PowerThresholds | None = None,
) -> tuple[bool, str, dict[str, Any] | None] | None:
    """Inspect an aggregate report using the same logic as individual reports."""
    query_id = agg_report.query_id
    query_data = agg_report.query_data

    # Determine query type from query_data (same logic as inspect_reports)
    query = get_query(query_data)
    if query is None:
        logger.error(f"Unable to parse query data for aggregate report query id: {query_id}")
        return None

    # Get query type from the query object
    query_type = query.__class__.__name__
    logger.info(f"CONFIG DEBUG: Aggregate report query type determined: {query_type}")

    # Check if query type is supported
    if not config_watcher.is_supported_query_type(query_type):
        logger.warning(f"CONFIG DEBUG: Aggregate report query type '{query_type}' is NOT supported")
        return None

    # Get configuration using the actual query type
    metrics = config_watcher.get_metrics_for_query(query_id, query_type)
    if metrics is None:
        logger.warning(f"No configuration available for aggregate report query {query_id[:16]}... of type {query_type}")
        return None

    # Get feed and trusted value (same logic as inspect_reports)
    query = get_query(query_data)
    if query is None:
        logger.error(f"Unable to parse query data for aggregate report query id: {query_id}")
        return None

    feed = await get_feed(query_id, query, logger)
    if feed is None:
        logger.error(f"Unable to get feed for aggregate report query id: {query_id}")
        return None

    trusted_value, _ = await fetch_value(feed)
    if trusted_value is None:
        logger.error(f"Unable to fetch trusted value for aggregate report query id: {query_id}")
        return None

    # Decode the aggregate hex value
    try:
        reported_value = decode_hex_value(agg_report.value)
    except (OverflowError, ValueError) as e:
        logger.error(f"🚨 Skipping aggregate report - invalid hex value: {e}")
        return None

    # Check if disputable using same logic
    alertable, disputable, diff = is_disputable(
        metrics.metric,
        metrics.alert_threshold,
        metrics.warning_threshold,
        reported_value,
        trusted_value,
        logger=logger,
    )

    if alertable is None:
        return None

    # Determine severity and action
    should_pause = False
    reason = ""
    power_info = None

    # Check if deviation exceeds pause threshold
    if diff >= metrics.pause_threshold:
        # Use power-based logic if Saga guard is enabled (both uri and power_thresholds provided)
        if uri and power_thresholds:
            reason = (
                f"Aggregate report deviation ({diff:.4f}) exceeds pause threshold "
                f"({metrics.pause_threshold:.4f}) - EVALUATING POWER THRESHOLDS"
            )

            power_info = await calculate_power_percentage(agg_report, uri, power_thresholds, logger)
            if power_info:
                should_pause = power_info["should_pause_immediately"]
                if power_info["should_pause_immediately"]:
                    immediate_threshold = power_thresholds.immediate_pause_threshold * 100
                    reason += (
                        f" | Power: {power_info['power_percentage']:.1f}% (>{immediate_threshold}%) - PAUSE IMMEDIATELY"
                    )
                elif power_info["should_pause_delayed"]:
                    delayed_threshold = power_thresholds.delayed_pause_threshold * 100
                    delay_hours = power_thresholds.pause_delay_hours
                    reason += (
                        f" | Power: {power_info['power_percentage']:.1f}% "
                        f"(>{delayed_threshold}%) - PAUSE AFTER {delay_hours}H DELAY"
                    )
                else:
                    should_pause = False
                    delayed_threshold = power_thresholds.delayed_pause_threshold * 100
                    reason += f" | Power: {power_info['power_percentage']:.1f}% (<{delayed_threshold}%) - NO PAUSE"
            else:
                # Fallback to immediate pause if power calculation fails
                should_pause = True
                reason += " | Power calculation failed - DEFAULTING TO IMMEDIATE PAUSE"
        else:
            # Traditional logic when Saga guard is not enabled or not properly configured
            should_pause = True
            reason = (
                f"Aggregate report deviation ({diff:.4f}) exceeds pause threshold "
                f"({metrics.pause_threshold:.4f}) - CIRCUIT BREAKER ACTIVATED"
            )

    elif disputable and metrics.warning_threshold > 0:
        # Use same category determination logic for non-pause alerts
        category = determine_dispute_category(
            category_thresholds={
                "major": metrics.major_threshold,
                "minor": metrics.minor_threshold,
                "warning": metrics.warning_threshold,
            },
            diff=diff,
        )
        reason = f"Aggregate report deviation ({diff:.4f}) exceeds {category} threshold"
    elif alertable:
        reason = f"Aggregate report deviation ({diff:.4f}) exceeds alert threshold"
    else:
        reason = f"acceptable deviation: {diff:.4f}"

    # Return appropriate format based on whether power thresholds were used
    if uri and power_thresholds:
        return should_pause, reason, power_info
    else:
        return should_pause, reason


async def calculate_power_percentage(
    agg_report: AggregateReport,
    uri: str,
    power_thresholds: PowerThresholds,
    logger: logging.Logger,
) -> dict[str, Any] | None:
    """Calculate the power percentage of an aggregate report relative to total non-jailed power.

    Args:
        agg_report: The aggregate report to analyze
        uri: RPC endpoint URI
        power_thresholds: Power threshold configuration
        logger: Logger instance

    Returns:
        Dict with power analysis results or None if query fails

    """
    try:
        # Query all reporters
        reporters_response = await query_reporters(uri, logger)
        if not reporters_response:
            logger.error("Failed to query reporters for power calculation")
            return None

        # Get aggregate power from the report
        aggregate_power = int(agg_report.aggregate_power)
        total_power = reporters_response.total_non_jailed_power

        if total_power == 0:
            logger.error("Total non-jailed power is 0 - cannot calculate percentage")
            return None

        # Calculate power percentage
        power_percentage = (aggregate_power / total_power) * 100.0

        # Determine pause decisions based on thresholds
        should_pause_immediately = power_percentage > (power_thresholds.immediate_pause_threshold * 100)
        should_pause_delayed = power_percentage > (power_thresholds.delayed_pause_threshold * 100)

        logger.info(
            f"Power analysis: aggregate={aggregate_power}, total={total_power}, "
            f"percentage={power_percentage:.2f}%, immediate_pause={should_pause_immediately}, "
            f"delayed_pause={should_pause_delayed}"
        )

        return {
            "aggregate_power": aggregate_power,
            "total_power": total_power,
            "power_percentage": power_percentage,
            "should_pause_immediately": should_pause_immediately,
            "should_pause_delayed": should_pause_delayed,
            "delay_hours": power_thresholds.pause_delay_hours,
            "immediate_threshold": power_thresholds.immediate_pause_threshold * 100,
            "delayed_threshold": power_thresholds.delayed_pause_threshold * 100,
        }

    except Exception as e:
        logger.error(f"Error calculating power percentage: {e}")
        return None


async def process_pending_pauses(
    pending_pauses: dict[str, PendingPause],
    saga_contract_manager: SagaContractManager | None,
    logger: logging.Logger,
    current_time: float,
) -> None:
    """Process pending pauses that have reached their delay timeout.

    Args:
        pending_pauses: Dictionary of pending pauses by query_id
        saga_contract_manager: Saga contract manager for pausing
        logger: Logger instance
        current_time: Current timestamp

    """
    expired_pauses = []

    for query_id, pending_pause in pending_pauses.items():
        delay_seconds = pending_pause.power_info["delay_hours"] * 3600
        if current_time >= pending_pause.trigger_time + delay_seconds:
            expired_pauses.append(query_id)

            logger.critical(
                f"🕐 DELAYED PAUSE TRIGGERED - {pending_pause.reason} - "
                f"Delay period ({pending_pause.power_info['delay_hours']}h) expired"
            )

            # Execute the pause
            if saga_contract_manager and pending_pause.contract_address != "0x0000000000000000000000000000000000000000":
                tx_hash, status = await saga_contract_manager.pause_contract(
                    pending_pause.contract_address, pending_pause.query_id
                )

                if tx_hash:
                    if status == "success":
                        logger.critical(f"🚨 DELAYED CONTRACT PAUSED SUCCESSFULLY - TxHash: {tx_hash}")
                    elif status == "timeout":
                        logger.warning(f"⏰ DELAYED PAUSE TRANSACTION PENDING - TxHash: {tx_hash}")
                else:
                    if status == "already_paused":
                        logger.warning(f"⚠️ CONTRACT ALREADY PAUSED - Address: {pending_pause.contract_address}")
                    else:
                        logger.error(
                            f"❌ DELAYED PAUSE FAILED - Address: {pending_pause.contract_address}, Status: {status}"
                        )
            else:
                logger.warning("⚠️ DELAYED PAUSE SKIPPED - Saga contract manager not available")

    # Remove expired pauses
    for query_id in expired_pauses:
        del pending_pauses[query_id]

    if expired_pauses:
        logger.info(f"Processed {len(expired_pauses)} expired pending pauses")


async def execute_contract_pause(
    saga_contract_manager: SagaContractManager | None,
    agg_report: AggregateReport,
    config_watcher: ConfigWatcher,
    logger: logging.Logger,
) -> None:
    """Execute contract pause for an aggregate report.

    Args:
        saga_contract_manager: Saga contract manager for pausing
        agg_report: The aggregate report triggering the pause
        config_watcher: Configuration watcher
        logger: Logger instance

    """
    if saga_contract_manager is not None:
        # Get contract address from config
        config = config_watcher.get_config()
        query_config = config.get(agg_report.query_id.lower())

        if query_config and query_config.get("datafeed_ca"):
            contract_address = query_config.get("datafeed_ca")

            # Skip if placeholder address
            if contract_address != "0x0000000000000000000000000000000000000000":
                tx_hash, status = await saga_contract_manager.pause_contract(contract_address, agg_report.query_id)
                if tx_hash:
                    if status == "success":
                        logger.critical(f"🚨 CONTRACT PAUSED SUCCESSFULLY - TxHash: {tx_hash}")
                    elif status == "timeout":
                        logger.warning(f"⏰ PAUSE TRANSACTION PENDING - TxHash: {tx_hash}")
                else:
                    if status == "already_paused":
                        logger.warning(f"⚠️ CONTRACT ALREADY PAUSED - Address: {contract_address}")
                    elif status == "not_guardian":
                        logger.error(f"❌ NOT AUTHORIZED - Account is not a guardian for contract {contract_address}")
                    elif status == "no_contract":
                        logger.error(f"❌ NO CONTRACT FOUND - Address: {contract_address}")
                    elif status == "invalid_address":
                        logger.error(f"❌ INVALID ADDRESS - Address: {contract_address}")
                    else:
                        logger.error(f"❌ FAILED TO PAUSE CONTRACT - Address: {contract_address}, Status: {status}")
            else:
                logger.warning(
                    f"⚠️ PAUSE SKIPPED - No valid contract address configured for query {agg_report.query_id[:16]}..."
                )
        else:
            logger.warning(f"⚠️ PAUSE SKIPPED - No contract address found in config for query {agg_report.query_id[:16]}...")
    else:
        logger.warning(
            "⚠️ PAUSE SKIPPED - Saga contract manager not initialized (check SAGA_EVM_RPC_URL and SAGA_PRIVATE_KEY)"
        )


async def agg_reports_queue_handler(
    agg_reports_q: asyncio.Queue,
    config_watcher: ConfigWatcher,
    logger: logging,
    saga_contract_manager: SagaContractManager | None = None,
    uri: str | None = None,
    power_thresholds: PowerThresholds | None = None,
) -> None:
    """Handle aggregate reports from the queue and check for pause conditions."""
    processed_reports = {}  # Track processed reports with timestamps to detect duplicates
    pending_pauses = {}  # Track pending pauses for delayed power thresholds {query_id: PendingPause}
    last_cleanup_time = time.time()
    last_pending_check = time.time()
    cleanup_interval = 24 * 60 * 60  # 24 hours in seconds
    pending_check_interval = 60  # Check pending pauses every minute

    while True:
        # Check for pending pauses that have reached their delay timeout
        current_time = time.time()
        if current_time - last_pending_check >= pending_check_interval:
            await process_pending_pauses(pending_pauses, saga_contract_manager, logger, current_time)
            last_pending_check = current_time

        agg_report: AggregateReport = await agg_reports_q.get()

        # Create a unique key for this report to detect duplicates (keep for safety)
        report_key = f"{agg_report.query_id}:{agg_report.height}:{agg_report.value}:{agg_report.micro_report_height}"
        current_time = time.time()

        # Periodic cleanup of old processed reports to prevent memory growth
        if current_time - last_cleanup_time >= cleanup_interval:
            initial_count = len(processed_reports)
            cutoff_time = current_time - cleanup_interval  # Remove entries older than 24 hours
            processed_reports = {k: v for k, v in processed_reports.items() if v >= cutoff_time}
            cleaned_count = initial_count - len(processed_reports)
            logger.info(f"🧹 Cleaned up {cleaned_count} old processed report entries (kept {len(processed_reports)})")
            last_cleanup_time = current_time

        if report_key in processed_reports:
            time_diff = current_time - processed_reports[report_key]
            logger.warning(f"🚨 DUPLICATE DETECTED! Report already processed {time_diff:.3f}s ago: {report_key}")
            # Skip processing duplicate
            agg_reports_q.task_done()
            continue
        else:
            processed_reports[report_key] = current_time

        # Log the aggregate report with decoded value for readability
        try:
            decoded_value = decode_hex_value(agg_report.value)
            logger.info(
                f"Aggregate Report found - qId: {agg_report.query_id[:16]}... value: {decoded_value:.6f} "
                f"power: {agg_report.aggregate_power} height: {agg_report.height}"
            )
        except (OverflowError, ValueError) as e:
            logger.error(f"🚨 Skipping aggregate report - invalid hex value: {e}")
            logger.info(
                f"Aggregate Report found - qId: {agg_report.query_id[:16]}... value: DECODE_ERROR "
                f"power: {agg_report.aggregate_power} height: {agg_report.height}"
            )
            agg_reports_q.task_done()
            continue

        # Inspect aggregate report using same logic as individual reports
        inspection_result = await inspect_aggregate_report(agg_report, config_watcher, logger, uri, power_thresholds)

        if inspection_result:
            # Handle both 2-tuple and 3-tuple return formats for backward compatibility
            if len(inspection_result) == 3:
                should_pause, reason, power_info = inspection_result
            else:
                should_pause, reason = inspection_result
                power_info = None

            # Check if this report should trigger immediate pause or delayed pause
            immediate_pause = should_pause
            delayed_pause = False

            if power_info and not should_pause:
                # Check if this meets delayed pause criteria
                delayed_pause = power_info.get("should_pause_delayed", False)

            if immediate_pause:
                logger.critical(f"🚨 CIRCUIT BREAKER ACTIVATED: {reason}")

                # Remove any existing pending pause for this query (superseded by immediate pause)
                if agg_report.query_id in pending_pauses:
                    del pending_pauses[agg_report.query_id]
                    logger.info(f"Removed pending pause for {agg_report.query_id[:16]}... (superseded by immediate pause)")

                # Execute immediate pause
                await execute_contract_pause(saga_contract_manager, agg_report, config_watcher, logger)

            elif delayed_pause:
                logger.critical(f"🕐 DELAYED PAUSE SCHEDULED: {reason}")

                # Get contract address for delayed pause
                config = config_watcher.get_config()
                query_config = config.get(agg_report.query_id.lower())

                if query_config and query_config.get("datafeed_ca"):
                    contract_address = query_config.get("datafeed_ca")

                    if contract_address != "0x0000000000000000000000000000000000000000":
                        # Check if there's already a pending pause for this query
                        if agg_report.query_id in pending_pauses:
                            logger.info(f"Pending pause already exists for {agg_report.query_id[:16]}...")
                        else:
                            # Create pending pause
                            pending_pause = PendingPause(
                                query_id=agg_report.query_id,
                                contract_address=contract_address,
                                trigger_time=current_time,
                                power_info=power_info,
                                agg_report=agg_report,
                                reason=reason,
                            )
                            pending_pauses[agg_report.query_id] = pending_pause

                            logger.critical(
                                f"⏰ PAUSE SCHEDULED - Will pause {contract_address} "
                                f"for query {agg_report.query_id[:16]}... "
                                f"in {power_info['delay_hours']} hours if not disputed"
                            )
                    else:
                        logger.warning(
                            f"⚠️ DELAYED PAUSE SKIPPED - No valid contract address for query {agg_report.query_id[:16]}..."
                        )
                else:
                    logger.warning(f"⚠️ DELAYED PAUSE SKIPPED - No contract config for query {agg_report.query_id[:16]}...")
            else:
                # Report validated - no action needed
                pass
        else:
            logger.warning("Could not validate aggregate report - configuration or trusted source unavailable")

        agg_reports_q.task_done()


async def inspect_evm_call_reports(
    reports: list[NewReport],
    feed: DataFeed,
    disputes_q: asyncio.Queue,
    query_id: str,
    metrics: Metrics,
    logger: logging,
) -> None:
    """Inspect reports for evm call query type and check if they are disputable.

    Reason they are different is because we need to specifically fetch values for each report
    because each value needs to be decoded and is dependant on the block timestamp in the value
    to fetch the trusted value from the relevant chain.

    reports: list of new_reports for a query id
    disputes_q: the queue to add disputes to for dispute processing
    query_id: the hash of the query data used to fetch the value.
    metrics: the metrics object for the query id
    logger: the logger object
    """
    # Get Web3 connection for the target chain
    chain_id = feed.query.chainId
    logger.info(f"EVMCall handler - inspecting {len(reports)} report(s) for chain_id: {chain_id}, query_id: {query_id}")

    w3 = get_web3_connection(chain_id)
    if w3 is None:
        logger.error(f"Failed to get Web3 connection for chain_id {chain_id}")
        return None

    logger.info(f"EVMCall handler - successfully connected to chain_id: {chain_id}")

    for r in reports:
        # Decode the reported value from hex to get (result_bytes, timestamp) tuple
        try:
            logger.info(
                f"EVMCall report decoded - chain_id: {chain_id}, contract: {feed.query.contractAddress}, value: {r.value}"
            )
            reported_value = feed.query.value_type.decode(bytes.fromhex(r.value))
        except Exception as e:
            logger.error(f"Failed to decode EVMCall reported value for chain_id {chain_id}: {e}")
            continue

        trusted_value = await get_evm_call_trusted_value(reported_value, feed, w3, chain_id)

        if trusted_value is None:
            logger.error(f"unable to fetch trusted value for query id: {query_id}")
            continue

        # EVMCall format: reporters submit abi.encode(abi.encode(value), timestamp)
        # reported_value[0] is abi.encode(value) which is already the raw bytes representation
        # trusted_value from eth_call is also raw bytes
        # Both are 32-byte representations of the contract return value, compare directly
        decoded_reported = reported_value[0]

        logger.info(f"Comparing reported: {decoded_reported.hex()} vs trusted: {trusted_value.hex()}")

        await inspect(r, decoded_reported, trusted_value, disputes_q, metrics, logger)
    return None


async def send_unsupported_query_alert(
    query_id: str,
    query_type: str,
    asset_pair: str,
    report: NewReport,
    logger: logging.Logger,
    description: str,
    try_decode: bool = False,
) -> None:
    """Send Discord alert for unsupported queries (foreign or unknown type).

    Args:
        query_id: The query ID
        query_type: The query type string
        asset_pair: Asset pair string (e.g. "eth/usd" or "Unknown")
        report: The NewReport object
        logger: Logger instance
        description: Alert description (e.g. "⚠️ **QUERY NOT FOUND IN TELLIOT OR CONFIGS**")
        try_decode: If True, attempt to decode value; if False, use raw hex

    """
    try:
        # Extract reported value for display
        if try_decode:
            try:
                query_obj = get_query(report.query_data)
                if query_obj:
                    reported_value = query_obj.value_type.decode(bytes.fromhex(report.value))
                else:
                    reported_value = report.value
            except Exception:
                reported_value = report.value
        else:
            reported_value = report.value

        # Build the alert message
        alert_msg = f"**QueryId:** {query_id}\n"
        alert_msg += f"**QueryType:** {query_type}\n"
        if asset_pair != "Unknown":
            alert_msg += f"**Asset pair:** {asset_pair}\n"
        alert_msg += f"**Value:** {reported_value}\n"
        alert_msg += f"**Reporter:** {report.reporter}\n"
        alert_msg += f"**Tx Hash:** {report.tx_hash}"

        logger.info(f"Unsupported query alert:\n{alert_msg}")
        generic_alert(alert_msg, description=description)

    except Exception as e:
        logger.error(f"Failed to send unsupported query alert: {e}")


async def inspect_trbbridge_reports(
    reports: list[NewReport],
    disputes_q: asyncio.Queue,
    query_id: str,
    metrics: Metrics,
    logger: logging,
) -> None:
    """Inspect reports for TRBBridge query type and check if they are disputable.

    For TRBBridge reports, we decode the deposit ID from queryData, fetch the deposit details
    from the contract's deposits mapping, and compare against the reported values.

    reports: list of new_reports for a query id
    disputes_q: the queue to add disputes to for dispute processing
    query_id: the hash of the query data used to fetch the value.
    metrics: the metrics object for the query id
    logger: the logger object
    """
    # Get TRBBridge configuration from environment variables, default to mainnet if not set
    contract_address = os.getenv("TRBBRIDGE_CONTRACT_ADDRESS")
    chain_id = int(os.getenv("TRBBRIDGE_CHAIN_ID", "1"))
    # Note: rpc_url is optional - get_trb_bridge_trusted_value will use unified connection manager
    # BRIDGE_CHAIN_RPC_URL is deprecated in favor of EVMCALL_RPC_URL_{chain_id}
    rpc_url = None  # Let trb_bridge.py handle RPC URL lookup via unified manager

    if not contract_address:
        logger.error("TRBBRIDGE_CONTRACT_ADDRESS environment variable is not set")
        return None

    logger.info(f"TRBBridge contract address: {contract_address}")
    logger.info(f"chain ID: {chain_id}")

    for r in reports:
        # Decode the reported value
        reported_details = decode_report_value(r.value)
        if reported_details is None:
            logger.error(f"Failed to decode reported value for TRBBridge query {query_id}")
            continue

        reported_eth_addr, reported_layer_addr, reported_amount, reported_tip = reported_details

        # Get trusted value from contract
        trusted_details = await get_trb_bridge_trusted_value(r.query_data, contract_address, chain_id, rpc_url, logger)

        if trusted_details is None:
            logger.error(f"Unable to fetch trusted value for TRBBridge query {query_id}")
            continue

        trusted_eth_addr, trusted_layer_addr, trusted_amount, trusted_tip = trusted_details

        # Create comparison structures for inspection
        reported_value = {
            "eth_address": reported_eth_addr,
            "layer_address": reported_layer_addr,
            "amount": reported_amount,
            "tip": reported_tip,
        }

        trusted_value = {
            "eth_address": trusted_eth_addr,
            "layer_address": trusted_layer_addr,
            "amount": trusted_amount,
            "tip": trusted_tip,
        }

        logger.info(f"TRBBridge Reported: {reported_value}")
        logger.info(f"TRBBridge Trusted: {trusted_value}")

        # Use string comparison for equality check (addresses and layer address)
        # and exact value comparison for amounts
        # Note: We don't need to store the matches result since we use exact equality for TRBBridge

        # For TRBBridge, we expect exact equality
        # Note: TRBBridge doesn't have a standard query object, pass None
        await inspect(r, reported_value, trusted_value, disputes_q, metrics, logger, query=None)

    return None


async def perform_dispute_verification(
    disputable: bool,
    diff: float,
    reported_value: Any,
    metrics: Metrics,
    logger: logging.Logger,
    trusted_value_fetcher: Any = None,
) -> dict[str, Any]:
    """Perform verification logic to determine if a dispute should be submitted.

    Handles both double-check logic (for SpotPrice with fetcher) and single-check logic
    (for EVMCall/TRBBridge without fetcher).

    Returns:
        Dict with keys: should_dispute, dispute_category, second_trusted_value,
        second_trusted_time, second_check_disputable, second_diff

    """
    result = {
        "should_dispute": False,
        "dispute_category": None,
        "second_trusted_value": None,
        "second_trusted_time": None,
        "second_check_disputable": None,
        "second_diff": None,
    }

    if disputable and trusted_value_fetcher is not None:
        # Double-check logic for SpotPrice queries
        logger.info(f"⏳ First trusted value check crossed threshold (diff: {diff}). Waiting 10 seconds for second check...")
        await asyncio.sleep(10)

        logger.info("📡 Fetching second trusted value for verification...")
        try:
            second_trusted_result = await trusted_value_fetcher()
            if second_trusted_result is not None:
                # fetch_value returns (value, timestamp) tuple
                result["second_trusted_value"] = (
                    second_trusted_result[0] if isinstance(second_trusted_result, tuple) else second_trusted_result
                )
                result["second_trusted_time"] = time.time()
                logger.info(f"✅ Second trusted value fetched: {result['second_trusted_value']}")

                # Compare reported value against second trusted value
                _, second_check_disputable, second_diff = is_disputable(
                    metrics.metric,
                    metrics.alert_threshold,
                    metrics.warning_threshold,
                    reported_value,
                    result["second_trusted_value"],
                    logger=logger,
                )
                result["second_check_disputable"] = second_check_disputable
                result["second_diff"] = second_diff

                # Only dispute if BOTH checks cross threshold
                if second_check_disputable:
                    logger.info(f"✅ Second check also crossed threshold (diff: {second_diff}). Proceeding with dispute.")
                    result["should_dispute"] = True

                    # Determine dispute category
                    if metrics.metric.lower() == "equality":
                        if metrics.warning_threshold == 1.0:
                            result["dispute_category"] = "warning"
                        elif metrics.minor_threshold == 1.0:
                            result["dispute_category"] = "minor"
                        elif metrics.major_threshold == 1.0:
                            result["dispute_category"] = "major"
                    else:
                        category = determine_dispute_category(
                            diff=second_diff,
                            category_thresholds={
                                "major": metrics.major_threshold,
                                "minor": metrics.minor_threshold,
                                "warning": metrics.warning_threshold,
                            },
                        )
                        if category is not None:
                            result["dispute_category"] = category
                else:
                    logger.info(f"⚠️ Second check did NOT cross threshold (diff: {second_diff}). Dispute cancelled.")
            else:
                logger.error("❌ Failed to fetch second trusted value. Cancelling dispute.")
        except Exception as e:
            logger.error(f"❌ Error fetching second trusted value: {e}. Cancelling dispute.")

    elif disputable and trusted_value_fetcher is None:
        # Single-check logic for EVMCall/TRBBridge queries
        logger.info(f"disputable: true, diff: {diff} (single-check mode)")

        # For equality metrics, determine dispute level based on which threshold is set to 1.0
        if metrics.metric.lower() == "equality":
            if metrics.warning_threshold == 1.0:
                result["dispute_category"] = "warning"
                result["should_dispute"] = True
                logger.info("Auto-disputing equality mismatch at warning level")
            elif metrics.minor_threshold == 1.0:
                result["dispute_category"] = "minor"
                result["should_dispute"] = True
                logger.info("Auto-disputing equality mismatch at minor level")
            elif metrics.major_threshold == 1.0:
                result["dispute_category"] = "major"
                result["should_dispute"] = True
                logger.info("Auto-disputing equality mismatch at major level")
            else:
                logger.debug("No dispute level configured for equality metric (no threshold set to 1.0)")
        else:
            # For other metrics, use traditional threshold-based logic
            category = determine_dispute_category(
                diff=diff,
                category_thresholds={
                    "major": metrics.major_threshold,
                    "minor": metrics.minor_threshold,
                    "warning": metrics.warning_threshold,
                },
            )
            if category is not None:
                result["dispute_category"] = category
                result["should_dispute"] = True

    return result


async def inspect(
    report: NewReport,
    reported_value: Any,
    trusted_value: Any,
    disputes_q: asyncio.Queue,
    metrics: Metrics,
    logger: logging,
    query: Any = None,
    trusted_value_fetcher: Any = None,
) -> None:
    """Inspect a new report and check if it is disputable.

    Args:
        report: The report to inspect
        reported_value: The decoded reported value
        trusted_value: The trusted value to compare against
        disputes_q: Queue for sending disputes
        metrics: Threshold metrics configuration
        logger: Logger instance
        query: Optional query object from telliot-feeds
        trusted_value_fetcher: Optional async callable that returns (value, timestamp) tuple for re-fetching trusted value

    """
    # Console output - concise 1-line summary
    query_type = report.query_type
    asset_info = ""
    if query_type == "SpotPrice" and query:
        if hasattr(query, "asset") and hasattr(query, "currency"):
            asset_info = f" {query.asset}/{query.currency}"

    # Format values for display
    if isinstance(reported_value, dict):
        reported_str = f"Dict[{len(reported_value)} fields]"
        trusted_str = f"Dict[{len(trusted_value)} fields]"
    elif isinstance(reported_value, bytes):
        reported_str = f"0x{reported_value.hex()}"
        trusted_str = f"0x{trusted_value.hex()}"
    else:
        reported_str = f"{reported_value}"
        trusted_str = f"{trusted_value}"

    console_logger.info(f"{query_type}{asset_info} | Reported: {reported_str} | Trusted: {trusted_str}")

    display = {
        "REPORTER": report.reporter,
        "QUERY_TYPE": report.query_type,
        "QUERY_ID": report.query_id,
        "AGGREGATE_METHOD": report.aggregate_method,
        "CYCLELIST": report.cyclelist,
        "POWER": report.power,
        "TIMESTAMP": int(report.timestamp),
        "TRUSTED_VALUE": trusted_value,
        "TX_HASH": report.tx_hash,
    }
    display["CURRENT_TIME"] = int(time.time() * 1000)
    display["TIME_DIFF"] = display["CURRENT_TIME"] - (int(report.timestamp))
    display["VALUE"] = reported_value

    # Store first trusted value timestamp
    first_trusted_value = trusted_value
    first_trusted_time = time.time()

    # compare values and check against threshold- three metrics(percentage, equality, range)
    alertable, disputable, diff = is_disputable(
        metrics.metric,
        metrics.alert_threshold,
        metrics.warning_threshold,
        reported_value,
        trusted_value,
        logger=logger,
    )
    if alertable is None:
        return None

    # Determine dispute level for Discord alert
    dispute_level = None
    is_disputable_flag = disputable  # Use the disputable value directly

    if disputable:
        if metrics.metric.lower() == "equality":
            if metrics.warning_threshold == 1.0:
                dispute_level = "warning"
            elif metrics.minor_threshold == 1.0:
                dispute_level = "minor"
            elif metrics.major_threshold == 1.0:
                dispute_level = "major"
        else:
            category = determine_dispute_category(
                diff=diff,
                category_thresholds={
                    "major": metrics.major_threshold,
                    "minor": metrics.minor_threshold,
                    "warning": metrics.warning_threshold,
                },
            )
            if category:
                dispute_level = category

    # Perform dispute verification (double-check for SpotPrice, single-check for others)
    verification_result = await perform_dispute_verification(
        disputable, diff, reported_value, metrics, logger, trusted_value_fetcher
    )

    should_dispute = verification_result["should_dispute"]
    dispute_category = verification_result["dispute_category"]
    second_trusted_value = verification_result["second_trusted_value"]
    second_trusted_time = verification_result["second_trusted_time"]
    second_check_disputable = verification_result["second_check_disputable"]
    second_diff = verification_result["second_diff"]

    # Send Discord alert AFTER double-check completes (or immediately if no double-check)
    if alertable or (disputable and trusted_value_fetcher is not None):
        import os
        from datetime import datetime

        from layer_values_monitor.discord import build_alert_message, format_difference, format_values
        from layer_values_monitor.dispute import get_disputer_address, validate_keyring_config
        from layer_values_monitor.telliot_feeds import extract_query_info

        query_info = extract_query_info(query, query_type=report.query_type)
        diff_str = format_difference(diff, metrics.metric)

        # Build message based on whether we did double-check
        if second_trusted_value is not None:
            # Double-check was performed - custom message format
            first_time_str = datetime.fromtimestamp(first_trusted_time).strftime("%Y-%m-%d %H:%M:%S")
            second_time_str = datetime.fromtimestamp(second_trusted_time).strftime("%Y-%m-%d %H:%M:%S")

            # Determine description based on dispute status
            if should_dispute:
                description = "🚨 **ATTEMPTING TO SEND DISPUTE**"
            else:
                description = "⚠️ **SECOND INSPECTION TRIGGERED, BUT NO DISPUTE SENT**"

            # Build custom message (without description - it's passed separately)
            msg = f"**QueryId:** {report.query_id}\n"
            msg += f"**Asset:** {query_info}\n"
            if report.query_type:
                msg += f"**QueryType:** {report.query_type}\n"
            if dispute_level:
                msg += f"**Level:** {dispute_level}\n"
            msg += f"**Reported Value:** {reported_value}\n"
            msg += f"**First Trusted Value:** {first_trusted_value} (retrieved at {first_time_str})\n"
            msg += f"**Second Trusted Value:** {second_trusted_value} (retrieved at {second_time_str})\n"
            msg += f"**First Check Difference:** {diff_str}\n"
            if second_check_disputable is not None:
                second_diff_str = format_difference(second_diff, metrics.metric)
                msg += f"**Second Check Difference:** {second_diff_str}\n"
            msg += f"**Reporter:** {report.reporter}\n"
            msg += f"**Power:** {report.power}\n"
            msg += f"**Tx Hash:** {report.tx_hash}\n"

            # Add disputer info if disputing
            if should_dispute and dispute_level != "warning":
                binary_path = os.getenv("LAYER_BINARY_PATH")
                key_name = os.getenv("LAYER_KEY_NAME")
                kb = os.getenv("LAYER_KEYRING_BACKEND")
                kdir = os.getenv("LAYER_KEYRING_DIR")

                if binary_path and key_name and kb and kdir:
                    if validate_keyring_config(binary_path, key_name, kb, kdir):
                        disputer_address = get_disputer_address(binary_path, key_name, kb, kdir)
                        if disputer_address:
                            msg += f"**Disputer:** {disputer_address}, {key_name}\n"
                    else:
                        msg += f"**Disputer:** {key_name} improperly configured, no dispute sent\n"

            logger.info(f"Double-check alert:\n{description}\n{msg}")
            generic_alert(msg, description=description)

        else:
            # Standard single-check alert (no fetcher or not disputable)
            value_display = format_values(reported_value, trusted_value, query_type=report.query_type)

            # Get disputer information based on dispute level and keyring config
            disputer_info = None
            if is_disputable_flag and dispute_level != "warning":
                # Only show disputer info for disputable alerts (not warnings)
                binary_path = os.getenv("LAYER_BINARY_PATH")
                key_name = os.getenv("LAYER_KEY_NAME")
                kb = os.getenv("LAYER_KEYRING_BACKEND")
                kdir = os.getenv("LAYER_KEYRING_DIR")

                if binary_path and key_name and kb and kdir:
                    # Check if keyring is properly configured
                    if validate_keyring_config(binary_path, key_name, kb, kdir):
                        disputer_address = get_disputer_address(binary_path, key_name, kb, kdir)
                        if disputer_address:
                            disputer_info = f"{disputer_address}, {key_name}"
                    else:
                        disputer_info = f"{key_name} improperly configured, no dispute sent"

            msg = build_alert_message(
                query_info=query_info,
                value_display=value_display,
                diff_str=diff_str,
                reporter=report.reporter,
                power=report.power,
                tx_hash=report.tx_hash,
                query_type=report.query_type,
                disputer_info=disputer_info,
                level=dispute_level,
            )

            # Determine description based on whether it's disputable
            if alertable and not is_disputable_flag:
                description = "⚠️ **ALERT THRESHOLD TRIGGERED, BUT NOT AT DISPUTE LEVEL**"
            else:
                description = "❗**FOUND SOMETHING**❗"

            logger.info(f"Alertable value detected:\n{msg}")
            generic_alert(msg, description=description)

    display["DISPUTABLE"] = disputable

    # Submit dispute if needed
    if should_dispute and dispute_category is not None:
        logger.info(f"Getting ready to send dispute tx... reported value: {reported_value}")
        fee = determine_dispute_fee(dispute_category, int(report.power))
        logger.info(f"Fee: {fee.__str__() + DENOM}")
        await disputes_q.put(Msg(report.reporter, report.query_id, report.meta_id, dispute_category, fee.__str__() + DENOM))
    add_to_table(display)
