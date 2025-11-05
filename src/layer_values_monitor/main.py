"""Layer values monitor."""

import argparse
import asyncio
import logging
import os
from functools import wraps
from pathlib import Path
from typing import Any

from layer_values_monitor.catchup import HeightTracker
from layer_values_monitor.config_watcher import ConfigWatcher, watch_config
from layer_values_monitor.custom_types import PowerThresholds
from layer_values_monitor.dispute import process_disputes
from layer_values_monitor.evm_connections import validate_rpc_connection
from layer_values_monitor.logger import logger
from layer_values_monitor.monitor import (
    agg_reports_queue_handler,
    listen_to_websocket_events,
    new_reports_queue_handler,
    raw_data_queue_handler,
)
from layer_values_monitor.saga_contract import create_saga_contract_manager

from dotenv import load_dotenv
from telliot_core.apps.telliot_config import TelliotConfig

for logger_name in logging.root.manager.loggerDict:
    if logger_name.startswith("telliot_feeds"):
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)




def async_run(f: Any) -> Any:
    """Wrap an async function to be called synchronously and handle keyboard interrupts."""

    @wraps(f)
    def wrapper(*args, **kwargs):  # noqa: ANN202
        try:
            return asyncio.run(f(*args, **kwargs))
        except KeyboardInterrupt:
            print("Exiting...")

    return wrapper


@async_run
async def start() -> None:
    """Start layer values monitor."""
    loaded = load_dotenv(override=True)
    if not loaded:
        raise ValueError("Failed to load environment variables")
    uri = os.getenv("URI")
    if uri is None:
        raise ValueError("URI not found in environment variables")
    chain_id = os.getenv("CHAIN_ID")
    if chain_id is None:
        raise ValueError("CHAIN_ID not found in environment variables")
    parser = argparse.ArgumentParser(description="Start values monitor")
    parser.add_argument(
        "binary_path",
        type=str,
        nargs="?",
        default=os.getenv("LAYER_BINARY_PATH"),
        help="Path to the Layer binary executable (can be set via LAYER_BINARY_PATH env var)",
    )
    parser.add_argument(
        "key_name",
        type=str,
        nargs="?",
        default=os.getenv("LAYER_KEY_NAME"),
        help="Name of the key to use for transactions (can be set via LAYER_KEY_NAME env var)",
    )
    parser.add_argument(
        "keyring_backend",
        type=str,
        nargs="?",
        default=os.getenv("LAYER_KEYRING_BACKEND"),
        help="Keyring backend (can be set via LAYER_KEYRING_BACKEND env var)",
    )
    parser.add_argument(
        "keyring_dir",
        type=str,
        nargs="?",
        default=os.getenv("LAYER_KEYRING_DIR"),
        help="Keyring directory (can be set via LAYER_KEYRING_DIR env var)",
    )
    parser.add_argument(
        "--payfrom-bond",
        action="store_true",
        default=os.getenv("PAYFROM_BOND", "").lower() in ("true", "1", "yes"),
        help="Pay dispute fee from bond (can be set via PAYFROM_BOND env var)",
    )
    parser.add_argument("--use-custom-config", action="store_true", help="Use custom config.toml")
    parser.add_argument(
        "--enable-saga-guard", action="store_true", help="Enable Saga aggregate report monitoring and contract pausing"
    )
    args = parser.parse_args()

    # Validate required arguments are provided either via env vars or command line
    if not args.binary_path:
        raise ValueError("binary_path is required (set LAYER_BINARY_PATH env var or provide as argument)")
    if not args.key_name:
        raise ValueError("key_name is required (set LAYER_KEY_NAME env var or provide as argument)")
    if not args.keyring_backend:
        raise ValueError("keyring_backend is required (set LAYER_KEYRING_BACKEND env var or provide as argument)")
    if not args.keyring_dir:
        raise ValueError("keyring_dir is required (set LAYER_KEYRING_DIR env var or provide as argument)")


    # Validate Saga environment variables if Saga guard is enabled
    power_thresholds = None
    saga_contract_manager = None
    if args.enable_saga_guard:
        # Set aggregate report power thresholds
        immediate_threshold = float(os.getenv("SAGA_IMMEDIATE_PAUSE_THRESHOLD", "0.66666666666"))
        delayed_threshold = float(os.getenv("SAGA_DELAYED_PAUSE_THRESHOLD", "0.3333333333"))

        power_thresholds = PowerThresholds(
            immediate_pause_threshold=immediate_threshold, delayed_pause_threshold=delayed_threshold
        )

        logger.info(
            f"💡 Power thresholds configured: immediate={immediate_threshold * 100}%, "
            f"delayed={delayed_threshold * 100}%, delay=12h (fixed)"
        )

        # Validate Saga RPC URLs and private key
        saga_rpc_urls = os.getenv("SAGA_RPC_URLS")
        saga_private_key = os.getenv("SAGA_PRIVATE_KEY")

        if not saga_rpc_urls:
            raise ValueError("SAGA_RPC_URLS environment variable is required when using --enable-saga-guard")
        if not saga_private_key:
            raise ValueError("SAGA_PRIVATE_KEY environment variable is required when using --enable-saga-guard")

        # Validate Saga RPC URL connectivity (test primary URL)
        logger.info("💡 Validating Saga EVM RPC connection...")
        primary_saga_url = saga_rpc_urls.split(',')[0].strip()
        is_valid, error_msg, saga_chain_id = validate_rpc_connection(primary_saga_url, "Saga", logger)
        if not is_valid:
            logger.warning(f"Primary Saga RPC validation failed: {error_msg}. Will try backups if configured.")

        saga_contract_manager = create_saga_contract_manager(logger)
        if saga_contract_manager:
            logger.info("💡 Saga contract manager initialized successfully")

    # Initialize config watcher
    config_path = Path(__file__).resolve().parents[2] / "config.toml"
    logger.info(f"CONFIG DEBUG: Initializing ConfigWatcher with path: {config_path}")
    config_watcher = ConfigWatcher(config_path)
    logger.info("💡 Config watcher initialized")

    # Log config summary
    logger.info("CONFIG DEBUG: Config summary:")
    logger.info(f"CONFIG DEBUG: - Global defaults: {len(config_watcher.global_defaults)} metric types")
    logger.info(f"CONFIG DEBUG: - Query types: {list(config_watcher.query_types.keys())}")
    logger.info(f"CONFIG DEBUG: - Query configs: {list(config_watcher.query_configs.keys())}")

    # Test config methods
    logger.info("CONFIG DEBUG: Testing config methods...")
    test_query_types = ["SpotPrice", "TrbBridge", "EvmCall", "UnknownType"]
    for query_type in test_query_types:
        is_supported = config_watcher.is_supported_query_type(query_type)
        logger.info(f"CONFIG DEBUG: - is_supported_query_type('{query_type}'): {is_supported}")
        if is_supported:
            query_type_info = config_watcher.get_query_type_info(query_type)
            logger.info(f"CONFIG DEBUG:   - get_query_type_info('{query_type}'): {query_type_info}")

    # Bounded queues to prevent memory exhaustion
    raw_data_queue = asyncio.Queue(maxsize=1000)  # Raw WebSocket events
    agg_reports_queue = asyncio.Queue(maxsize=500)  # Aggregate reports for Saga Guard
    new_reports_queue = asyncio.Queue(maxsize=200)  # Batched new reports
    disputes_queue = asyncio.Queue(maxsize=100)  # Dispute submissions
    logger.info("💡 Message queues initialized")

    # TelliotConfig is used for non-EVMCall query types (SpotPrice, etc.)
    # EVMCall uses direct Web3 connections via get_web3_connection()
    cfg = TelliotConfig()
    cfg.main.chain_id = 1
    logger.info("💡 TelliotConfig initialized for standard query types")

    # Height tracker for missed block detection
    max_catchup_blocks = int(os.getenv("MAX_CATCHUP_BLOCKS", "15"))
    height_tracker = HeightTracker(max_catchup_blocks=max_catchup_blocks)

    logger.info(f"💡 Catch-up configuration: max {max_catchup_blocks} blocks to prevent stale price comparisons")

    # Initialize row counter for CSV file management
    from layer_values_monitor.utils import initialize_row_counter

    initialize_row_counter()

    # TODO: validate user options to check if they conflict
    try:
        # Build list of queries to subscribe to
        queries = ["new_report.reporter_power > 0"]

        # Add aggregate report query if Saga guard is enabled
        if args.enable_saga_guard:
            queries.append("aggregate_report.aggregate_power > 0")

        # Build list of tasks to run concurrently
        tasks = [
            listen_to_websocket_events(uri, queries, raw_data_queue, logger, height_tracker),
            raw_data_queue_handler(
                raw_data_queue,
                new_reports_queue,
                agg_reports_queue if args.enable_saga_guard else None,
                logger,
                height_tracker,
            ),
            new_reports_queue_handler(new_reports_queue, disputes_queue, config_watcher, logger),
            process_disputes(
                disputes_q=disputes_queue,
                binary_path=args.binary_path,
                key_name=args.key_name,
                kb=args.keyring_backend,
                kdir=args.keyring_dir,
                rpc=f"http://{uri}",
                chain_id=chain_id,
                payfrom_bond=args.payfrom_bond,
                logger=logger,
            ),
            watch_config(config_watcher),
        ]

        # Only add Saga-related tasks if enabled
        if args.enable_saga_guard:
            tasks.append(
                agg_reports_queue_handler(
                    agg_reports_queue, config_watcher, logger, saga_contract_manager, uri, power_thresholds
                )
            )

        logger.info("💡 Starting Layer Values Monitor...")
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        print("shutting down running tasks")
        raise


if __name__ == "__main__":
    start()
