"""Layer values monitor."""

import argparse
import asyncio
import logging
import os
from functools import wraps
from pathlib import Path
from typing import Any

from layer_values_monitor.config_watcher import ConfigWatcher, watch_config
from layer_values_monitor.dispute import process_disputes
from layer_values_monitor.logger import logger
from layer_values_monitor.monitor import (
    agg_reports_queue_handler,
    listen_to_websocket_events,
    new_reports_queue_handler,
    raw_data_queue_handler,
)
from layer_values_monitor.saga_contract import create_saga_contract_manager
from layer_values_monitor.threshold_config import ThresholdConfig

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
    # percentage
    parser.add_argument("--global-percentage-alert-threshold", type=float, help="Global percent threshold")
    parser.add_argument(
        "--global-percentage-warning-threshold", default=0.0, type=float, help="Global percentage for a warning dispute cat"
    )
    parser.add_argument(
        "--global-percentage-minor-threshold", default=0.0, type=float, help="Global percentage for a minor dispute cat"
    )
    parser.add_argument(
        "--global-percentage-major-threshold", default=0.0, type=float, help="Global percentage for a major dispute cat"
    )
    # range
    parser.add_argument("--global-range-alert-threshold", default=0.0, type=float, help="Global range threshold")
    parser.add_argument(
        "--global-range-warning-threshold", default=0.0, type=float, help="Global range for a warning dispute cat"
    )
    parser.add_argument(
        "--global-range-minor-threshold", default=0.0, type=float, help="Global range for a minor dispute cat"
    )
    parser.add_argument(
        "--global-range-major-threshold", default=0.0, type=float, help="Global range for a major dispute cat"
    )
    # equality
    parser.add_argument("--global-equality-alert-threshold", default=False, type=bool, help="Global equality threshold")
    parser.add_argument(
        "--global-equality-warning-threshold", default=False, type=bool, help="Global equality for a warning dispute cat"
    )
    parser.add_argument(
        "--global-equality-minor-threshold", default=False, type=bool, help="Global equality for a minor dispute cat"
    )
    parser.add_argument(
        "--global-equality-major-threshold", default=False, type=bool, help="Global equality for a major dispute cat"
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
    if args.enable_saga_guard:
        saga_rpc_url = os.getenv("SAGA_EVM_RPC_URL")
        saga_private_key = os.getenv("SAGA_PRIVATE_KEY")

        if not saga_rpc_url:
            raise ValueError("SAGA_EVM_RPC_URL environment variable is required when using --enable-saga-guard")
        if not saga_private_key:
            raise ValueError("SAGA_PRIVATE_KEY environment variable is required when using --enable-saga-guard")

    threshold_config = ThresholdConfig.from_args(args)

    # Initialize config watcher
    config_path = Path(__file__).resolve().parents[2] / "config.toml"
    config_watcher = ConfigWatcher(config_path)

    # Initialize Saga contract manager for pausing contracts (if enabled)
    saga_contract_manager = None
    if args.enable_saga_guard:
        saga_contract_manager = create_saga_contract_manager(logger)

    # Bounded queues to prevent memory exhaustion
    raw_data_queue = asyncio.Queue(maxsize=1000)  # Raw WebSocket events
    agg_reports_queue = asyncio.Queue(maxsize=500)  # Aggregate reports for Saga Guard
    new_reports_queue = asyncio.Queue(maxsize=200)  # Batched new reports
    disputes_queue = asyncio.Queue(maxsize=100)  # Dispute submissions
    cfg = TelliotConfig()
    cfg.main.chain_id = 1

    # TODO: validate user options to check if they conflict
    try:
        # Build list of queries to subscribe to
        queries = ["new_report.reporter_power > 0"]

        # Add aggregate report query if Saga guard is enabled
        if args.enable_saga_guard:
            queries.append("aggregate_report.aggregate_power > 0")

        # Build list of tasks to run concurrently
        tasks = [
            listen_to_websocket_events(uri, queries, raw_data_queue, logger),
            raw_data_queue_handler(
                raw_data_queue,
                new_reports_queue,
                agg_reports_queue if args.enable_saga_guard else None,
                logger=logger,
            ),
            new_reports_queue_handler(new_reports_queue, disputes_queue, config_watcher, logger, threshold_config),
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
                agg_reports_queue_handler(agg_reports_queue, config_watcher, logger, threshold_config, saga_contract_manager)
            )

        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        print("shutting down running tasks")
        raise


if __name__ == "__main__":
    start()
