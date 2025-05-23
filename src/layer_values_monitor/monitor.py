"""Values monitor."""

import asyncio
import json
import logging
import random
import time
from typing import Any

from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.constants import DENOM
from layer_values_monitor.custom_types import Metrics, Msg, NewReport
from layer_values_monitor.discord import generic_alert
from layer_values_monitor.dispute import (
    determine_dispute_category,
    determine_dispute_fee,
)
from layer_values_monitor.evm_call import get_evm_call_trusted_value
from layer_values_monitor.telliot_feeds import fetch_value, get_feed, get_query
from layer_values_monitor.threshold_config import ThresholdConfig
from layer_values_monitor.utils import add_to_table, get_metric, remove_0x_prefix

import websockets
from telliot_feeds.datafeed import DataFeed


async def listen_to_new_report_events(uri: str, q: asyncio.Queue, logger: logging) -> None:
    """Connect to a layer websocket and fetch new reports and add them to queue for monitoring.

    uri: address to chain (ie ws://localhost:26657/websocket)
    q: queue to store raw response for later processing
    logger:
    """
    logger.info("Starting WebSocket connection...")
    query = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "subscribe",
            "id": 1,
            "params": {"query": "new_report.reporter_power > 0"},
        }
    )
    uri = f"ws://{uri}/websocket"
    retry_count = 0
    base_delay = 1
    max_delay = 60

    while True:
        try:
            logger.info(f"Connecting to WebSocket at {uri}... (Attempt {retry_count + 1})")
            async with websockets.connect(uri) as websocket:
                await websocket.send(query)
                logger.info("Successfully subscribed to events.")
                # Reset retry count on successful connection
                retry_count = 0
                while True:
                    response = await websocket.recv()
                    await q.put(json.loads(response))

        except websockets.ConnectionClosed as e:
            logger.warning(f"WebSocket connection closed: {e}")
        except websockets.WebSocketException as e:
            logger.error(f"WebSocket error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
        logger.info("going through the retry phase since connection was closed")
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
    logger: logging,
    max_iterations: float = float("inf"),  # use iterations var for testing purposes instead of using a while loop
) -> None:
    """Inspect reports in reports queue and process to see if they should disputed."""
    logger.info("Inspecting reports...")
    iterations = 0
    reports_collections: dict[str, list[NewReport]] = {}
    # current height being collected for
    current_height = 0
    while iterations < max_iterations:
        iterations += 1
        raw_data: dict[str, Any] = await raw_data_q.get()
        raw_data_q.task_done()

        result: dict[str, Any] = raw_data.get("result")
        if result is None:
            continue

        events = result.get("events")
        if events is None:
            continue

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
        except (KeyError, IndexError) as e:
            logger.warning(f"malformed report returned by websocket: {e.__str__()}")
            continue

        # check if height has incremented from the reports we are collecting
        # then clear collection and start a new collection
        if height > current_height:
            if len(reports_collections) > 0:
                await new_reports_q.put(dict(reports_collections))
                reports_collections.clear()
            current_height = height

        reports_collected = reports_collections.get(report.query_id, None)
        if reports_collected is None:
            reports_collections[report.query_id] = [report]
        else:
            reports_collections[report.query_id].append(report)


async def inspect_reports(
    reports: list[NewReport],
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher,
    logger: logging,
    threshold_config: ThresholdConfig,
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
    _config: dict[str, str] = config_watcher.get_config().get(query_id.lower())
    if _config is None:
        # use globals if no specific config for query id
        metrics = get_metric(
            query_type,
            logger,
            threshold_config,
        )
        # handle not supported query types
        if metrics is None:
            logger.error("no custom configuration and no global thresholds set so can't check value")
            return None
    else:
        metrics = Metrics(
            metric=_config.get("metric"),
            alert_threshold=_config.get("alert_threshold"),
            warning_threshold=_config.get("warning_threshold"),
            minor_threshold=_config.get("minor_threshold"),
            major_threshold=_config.get("major_threshold"),
        )

        if any(
            x is None for x in [
                metrics.metric,
                metrics.alert_threshold,
                metrics.warning_threshold,
                metrics.minor_threshold,
                metrics.major_threshold,
            ]
        ):
            logger.error(f"config for {query_id} not set properly")
            return None

    query = get_query(query_data)
    feed = await get_feed(query_id, query, logger)

    if query_type.lower() == "evmcall":
        return await inspect_evm_call_reports(
            reports,
            feed,
            disputes_q,
            query_id,
            metrics,
            logger,
        )

    trusted_value, _ = await fetch_value(feed)
    if trusted_value is None:
        logger.error(f"unable to fetch trusted value for query id: {query_id}")
        return None
    for r in reports:
        reported_value = query.value_type.decode(bytes.fromhex(r.value))
        await inspect(r, reported_value, trusted_value, disputes_q, metrics, logger)

    return None


async def new_reports_queue_handler(
    new_reports_q: asyncio.Queue,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher,
    logger: logging,
    threshold_config: ThresholdConfig,
) -> None:
    """Handle new reports from the queue and process them."""
    logger.debug("Handling new reports...")
    running_tasks = set()

    while True:
        new_reports: dict = await new_reports_q.get()

        for report in new_reports.values():
            # Create a task for each query id
            task = asyncio.create_task(inspect_reports(report, disputes_q, config_watcher, logger, threshold_config))

            # Add task tracking and cleanup
            running_tasks.add(task)
            task.add_done_callback(running_tasks.discard)

            # Handle exceptions
            def handle_task_exception(t: asyncio.Task) -> None:
                if t.exception():
                    logger.error(f"Task raised exception: {t.exception()}")

            task.add_done_callback(handle_task_exception)

        new_reports_q.task_done()


def is_disputable(
    metric: str, alert_threshold: float, dispute_threshold: float, reported_value: Any, trusted_value: Any, logger: logging
) -> tuple[bool, bool, float] | tuple[None, None, None]:
    """Determine if a value is disputable based on comparison with a trusted value using specified metrics and thresholds."""
    if metric.lower() == "percentage":
        percent_diff: float = (reported_value - trusted_value) / trusted_value
        percent_diff = abs(percent_diff)
        logger.debug(f"percent diff: {percent_diff}, reported value: {reported_value} - trusted value: {trusted_value}")
        if dispute_threshold == 0:
            return percent_diff >= alert_threshold, False, percent_diff
        return percent_diff >= alert_threshold, percent_diff >= dispute_threshold, percent_diff

    if metric.lower() == "equality":
        logger.info(f"checking equality of values, reported value: {reported_value}, trusted value: {trusted_value}")
        # TODO: should this be a string comparison?
        is_not_equal = remove_0x_prefix(str(reported_value)).lower() != remove_0x_prefix(str(trusted_value).lower())
        if dispute_threshold == 0:
            return is_not_equal, False, float(is_not_equal)
        return is_not_equal, is_not_equal, float(is_not_equal)

    if metric.lower() == "range":
        diff = float(abs(reported_value - trusted_value))
        if dispute_threshold == 0:
            return diff >= alert_threshold, False, diff
        return diff >= alert_threshold, diff >= dispute_threshold, diff

    logger.error(f"unsupported metric: {metric}")
    return None, None, None


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
    feed: the data feed object for the query id
    """
    for r in reports:
        trusted_value = await get_evm_call_trusted_value(r.value, feed)
        if trusted_value is None:
            logger.error(f"unable to fetch trusted value for query id: {query_id}")
            continue
        await inspect(r, r.value, trusted_value, disputes_q, metrics, logger)
    return None


async def inspect(
    report: NewReport,
    reported_value: Any,
    trusted_value: Any,
    disputes_q: asyncio.Queue,
    metrics: Metrics,
    logger: logging,
) -> None:
    """Inspect a new report and check if it is disputable."""
    display = {
        "REPORTER": report.reporter,
        "QUERY_TYPE": report.query_type,
        "QUERY_ID": report.query_id,
        "AGGREGATE_METHOD": report.aggregate_method,
        "CYCLELIST": report.cyclelist,
        "POWER": report.power,
        "TIMESTAMP": report.timestamp,
        "TRUSTED_VALUE": trusted_value,
        "TX_HASH": report.tx_hash,
    }
    display["CURRENT_TIME"] = int(time.time() * 1000)
    display["TIME_DIFF"] = display["CURRENT_TIME"] - (int(report.timestamp))
    display["VALUE"] = reported_value
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
    if alertable:
        msg = f"found an alertable value. trusted value: {trusted_value}, reported value: {reported_value}"
        logger.info(msg)
        generic_alert(msg + f" tx hash: {report.tx_hash}")

    display["DISPUTABLE"] = disputable

    if disputable and metrics.warning_threshold > 0:
        logger.info(f"found a disputable value. trusted value: {trusted_value}, reported value: {reported_value}")
        # if dispute add message to dispute queue
        category = determine_dispute_category(
            category_thresholds={
                "major": metrics.major_threshold,
                "minor": metrics.minor_threshold,
                "warning": metrics.warning_threshold,
            },
            diff=diff,
        )
        if category is not None:
            fee = determine_dispute_fee(category, int(report.power))
            await disputes_q.put(Msg(report.reporter, report.query_id, report.meta_id, category, fee.__str__() + DENOM))
    add_to_table(display)
