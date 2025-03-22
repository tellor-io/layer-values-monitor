"""Values monitor."""

import asyncio
import json
import logging
import os
import random
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Literal

from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.discord import generic_alert
from layer_values_monitor.evm_call import get_evm_call_trusted_value
from layer_values_monitor.logger import logger
from layer_values_monitor.propose_dispute import (
    DisputeCategory,
    determine_dispute_category,
    determine_dispute_fee,
    propose_msg,
)
from layer_values_monitor.types_metric import GlobalMetric

import pandas as pd
import websockets
from clamfig.base import Registry
from eth_abi import decode
from telliot_feeds.datafeed import DataFeed
from telliot_feeds.datasource import DataSource
from telliot_feeds.feeds import CATALOG_FEEDS, DATAFEED_BUILDER_MAPPING
from telliot_feeds.queries.abi_query import AbiQuery
from telliot_feeds.queries.json_query import JsonQuery
from telliot_feeds.queries.query_catalog import query_catalog

for logger_name in logging.root.manager.loggerDict:
    if logger_name.startswith("telliot_feeds"):
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)


table = deque(maxlen=10)
log_file = "table.csv"

Metric = Literal["percentage", "range", "equality"]
DENOM = "loya"


@dataclass
class NewReport:
    """Store information about a newly submitted report."""

    query_type: str
    query_data: str
    query_id: str
    value: str
    aggregate_method: str
    cyclelist: str
    power: str
    reporter: str
    timestamp: str
    meta_id: str
    tx_hash: str


@dataclass
class Msg:
    """Represent a dispute message."""

    reporter: str
    query_id: str
    meta_id: str
    category: DisputeCategory
    fee: str


@dataclass
class Metrics:
    """Define threshold metrics for setting user configured metrics."""

    metric: str
    alert_threshold: float
    warning_threshold: float
    minor_threshold: float
    major_threshold: float


async def listen_to_new_report_events(uri: str, q: asyncio.Queue) -> None:
    """Connect to a layer websocket and fetch new reports and add them to reports queue for monitoring."""
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
                    await q.put(response)  # Add message to queue

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


async def inspect_reports(
    reports_q: asyncio.Queue,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher,
    max_iterations: float = float("inf"),  # use iterations var for testing purposes instead of using a while loop
    global_percentage_alert_threshold: float | None = None,
    global_percentage_warning_threshold: float | None = None,
    global_percentage_minor_threshold: float | None = None,
    global_percentage_major_threshold: float | None = None,
    global_range_alert_threshold: float | None = None,
    global_range_warning_threshold: float | None = None,
    global_range_minor_threshold: float | None = None,
    global_range_major_threshold: float | None = None,
    global_equality_warning_threshold: float | None = None,
    global_equality_minor_threshold: float | None = None,
    global_equality_major_threshold: float | None = None,
) -> None:
    """Inspect reports in reports queue and process to see if they should disputed."""
    logger.info("Inspecting reports...")
    iterations = 0

    while iterations < max_iterations:
        iterations += 1
        display = {}
        reports = await reports_q.get()
        reports_q.task_done()  # Mark as done for testing

        data: dict[str, Any] = json.loads(reports)
        result: dict[str, Any] = data.get("result")
        if result is None:
            continue

        events = result.get("events")
        if events is None:
            continue

        try:
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
        except IndexError as e:
            logger.warning(f"malformed report returned by websocker: {e.__str__()}")
            continue

        display["REPORTER"] = report.reporter
        display["QUERY_TYPE"] = report.query_type
        display["QUERY_ID"] = report.query_id
        display["AGGREGATE_METHOD"] = report.aggregate_method
        display["CYCLELIST"] = report.cyclelist
        display["POWER"] = report.power
        display["TIMESTAMP"] = report.timestamp
        display["TX_HASH"] = report.tx_hash

        query_data_bytes = bytes.fromhex(report.query_data)
        # check if this query has a custom config
        _config: dict[str, str] = config_watcher.get_config().get(report.query_id.lower())

        if _config is None:
            # use globals if no specific config for query id
            metrics = get_metric(
                report.query_type,
                global_percentage_alert_threshold=global_percentage_alert_threshold,
                global_percentage_warning_threshold=global_percentage_warning_threshold,
                global_percentage_minor_threshold=global_percentage_minor_threshold,
                global_percentage_major_threshold=global_percentage_major_threshold,
                global_range_alert_threshold=global_range_alert_threshold,
                global_range_warning_threshold=global_range_warning_threshold,
                global_range_minor_threshold=global_range_minor_threshold,
                global_range_major_threshold=global_range_major_threshold,
                global_equality_warning_threshold=global_equality_warning_threshold,
                global_equality_minor_threshold=global_equality_minor_threshold,
                global_equality_major_threshold=global_equality_major_threshold,
            )
            # handle not supported q types
            if metrics is None:
                logger.error("no custom configuration and no global thresholds set so can't check value")
                continue
        else:
            metrics = Metrics(
                metric=_config.get("metric"),
                alert_threshold=_config.get("alert_threshold"),
                warning_threshold=_config.get("warning_threshold"),
                minor_threshold=_config.get("minor_threshold"),
                major_threshold=_config.get("major_threshold"),
            )

            if any(
                [
                    not metrics.metric,
                    not metrics.alert_threshold,
                    not metrics.warning_threshold,
                    not metrics.minor_threshold,
                    not metrics.major_threshold,
                ]
            ):
                logger.error(f"config for {report.query_id} not set properly")
                continue

        query = get_query_from_data(query_data_bytes)

        catalog_entry = query_catalog.find(query_id=report.query_id)
        if len(catalog_entry) == 0:
            source = get_source_from_data(query_data_bytes)
            if source is None:
                logger.warning("no source found in telliot feeds found for query")
                continue
            feed = DataFeed(query=query, source=source)
        else:
            feed = get_feed_from_catalog(catalog_entry[0].tag)

        reported_value = query.value_type.decode(bytes.fromhex(report.value))
        display["VALUE"] = reported_value
        # handle special case where query type is EVMCall
        if report.query_type.lower() == "evmcall":
            trusted_value = await get_evm_call_trusted_value(reported_value, feed)
        else:
            trusted_value, _ = await feed.source.fetch_new_datapoint()
            if trusted_value is None:
                logger.warning(
                    f"can't compare values; unable to fetch trusted value from api, query type: {report.query_type}"
                )
                continue
        display["TRUSTED_VALUE"] = trusted_value
        # compare values and check against threshold- three metrics(percentage, equality, range)
        alertable, disputable, diff = is_disputable(
            metrics.metric, metrics.alert_threshold, metrics.warning_threshold, reported_value, trusted_value
        )
        if alertable is None:
            continue
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


def get_query_from_data(query_data: bytes) -> AbiQuery | JsonQuery | None:
    """Get query give query data from telliot-feeds."""
    for q_type in (JsonQuery, AbiQuery):
        try:
            return q_type.get_query_from_data(query_data)
        except ValueError:
            pass
    return None


def get_source_from_data(query_data: bytes) -> DataSource | None:
    """Recreate data source using query type thats decoded from query data field."""
    try:
        query_type, encoded_param_values = decode(["string", "bytes"], query_data)
    except OverflowError:
        logger.error("OverflowError while decoding query data.")
        return None
    try:
        cls = Registry.registry[query_type]
    except KeyError:
        logger.error(f"Unsupported query type: {query_type}")
        return None
    try:
        params_abi = cls.abi
    except AttributeError:
        logger.error(f"query type {query_type} doesn't have abi attirbute to decode params")
        return None
    param_names = [p["name"] for p in params_abi]
    param_types = [p["type"] for p in params_abi]
    param_values = decode(param_types, encoded_param_values)

    feed_builder = DATAFEED_BUILDER_MAPPING.get(query_type)
    if feed_builder is None:
        logger.error(f"query type {query_type} not supported by datafeed builder")
        return None
    source = feed_builder.source
    for key, value in zip(param_names, param_values, strict=False):
        setattr(source, key, value)
    return source


def get_feed_from_catalog(tag: str) -> DataFeed | None:
    """Get feed from telliot-feeds mapping if exists."""
    return CATALOG_FEEDS.get(tag)


def is_disputable(
    metric: str, alert_threshold: float, dispute_threshold: float, reported_value: Any, trusted_value: Any
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


def get_metric(
    query_type: str,
    global_percentage_alert_threshold: float,
    global_percentage_warning_threshold: float,
    global_percentage_minor_threshold: float,
    global_percentage_major_threshold: float,
    global_range_alert_threshold: float,
    global_range_warning_threshold: float,
    global_range_minor_threshold: float,
    global_range_major_threshold: float,
    global_equality_warning_threshold: float,
    global_equality_minor_threshold: float,
    global_equality_major_threshold: float,
) -> Metrics | None:
    """Return Metrics/Thresholds given a query type."""
    try:
        metric = GlobalMetric[query_type.upper()].value
    except KeyError:
        logger.error(f"query type {query_type} not found in global metrics")
        print(f"ERROR: query type {query_type} not found in global metrics")
        return None
    if metric == "percentage":
        return Metrics(
            metric=metric,
            alert_threshold=global_percentage_alert_threshold,
            warning_threshold=global_percentage_warning_threshold,
            minor_threshold=global_percentage_minor_threshold,
            major_threshold=global_percentage_major_threshold,
        )
    elif metric == "range":
        return Metrics(
            metric=metric,
            alert_threshold=global_range_alert_threshold,
            warning_threshold=global_range_warning_threshold,
            minor_threshold=global_range_minor_threshold,
            major_threshold=global_range_major_threshold,
        )
    elif metric == "equality":
        return Metrics(
            metric=metric,
            alert_threshold=1.0,
            warning_threshold=global_equality_warning_threshold,
            minor_threshold=global_equality_minor_threshold,
            major_threshold=global_equality_major_threshold,
        )


def remove_0x_prefix(s: str) -> str:
    """Remove 0x prefix if there from hex string."""
    if s.startswith("0x"):
        return s[2:]
    return s


def add_to_table(entry: dict[str, str]) -> None:
    """Add entry to table and clear old line."""
    global table
    table.append(entry)
    os.system("clear")
    df = pd.DataFrame(table)

    print(df.to_string(index=False, justify="center"))

    if os.path.exists(log_file):
        # if file exists then just append to it
        pd.DataFrame([entry]).to_csv(log_file, mode="a", header=False, index=False)
    else:
        # else create file and add header
        pd.DataFrame([entry]).to_csv(log_file, mode="w", header=True, index=False)


async def process_disputes(
    disputes_q: asyncio.Queue,
    binary_path: str,
    key_name: str,
    chain_id: str,
    rpc: str,
    kb: str,
    kdir: str,
    payfrom_bond: bool,
) -> None:
    """Process dispute messages from queue and submit them to the blockchain."""
    while True:
        dispute: Msg = await disputes_q.get()
        disputes_q.task_done()
        if dispute is None:
            continue
        time.sleep(2)
        logger.info(
            f"sending a dispute msg to layer:\n \
                    Reporter: {dispute.reporter}\n \
                    Query ID: {dispute.query_id} \
                    "
        )
        _ = propose_msg(
            binary_path=binary_path,
            key_name=key_name,
            chain_id=chain_id,
            rpc=rpc,
            kb=kb,
            kdir=kdir,
            reporter=dispute.reporter,
            query_id=dispute.query_id,
            meta_id=dispute.meta_id,
            dispute_category=dispute.category,
            fee=dispute.fee,
            payfrom_bond=str(payfrom_bond),
        )
