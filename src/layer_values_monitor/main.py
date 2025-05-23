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
    listen_to_new_report_events,
    new_reports_queue_handler,
    raw_data_queue_handler,
)
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
    parser.add_argument("binary_path", type=str, help="Path to the Layer binary executable")
    parser.add_argument("key_name", type=str, help="Name of the key to use for transactions")
    parser.add_argument("keyring_backend", type=str, help="Keyring backend")
    parser.add_argument("keyring_dir", type=str, help="Keyring directory")
    parser.add_argument("--payfrom-bond", action="store_true", help="Pay dispute fee from bond")
    parser.add_argument("--use-custom-config", action="store_true", help="Use custom config.toml")
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

    threshold_config = ThresholdConfig.from_args(args)

    # Initialize config watcher
    config_path = Path(__file__).resolve().parents[2] / "config.toml"
    config_watcher = ConfigWatcher(config_path)

    raw_data_queue = asyncio.Queue()
    new_reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()
    cfg = TelliotConfig()
    cfg.main.chain_id = 1

    # TODO: validate user options to check if they conflict
    try:
        await asyncio.gather(
            listen_to_new_report_events(uri, raw_data_queue, logger),
            raw_data_queue_handler(
                raw_data_queue,
                new_reports_queue,
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
        )
    except asyncio.CancelledError:
        print("shutting down running tasks")
        raise


if __name__ == "__main__":
    start()
