"""Layer values monitor."""

import argparse
import asyncio
import os
from functools import wraps
from pathlib import Path
from typing import Any

from layer_values_monitor.config_watcher import ConfigWatcher, watch_config
from layer_values_monitor.monitor import (
    inspect_reports,
    listen_to_new_report_events,
    process_disputes,
)

from dotenv import load_dotenv
from telliot_core.apps.telliot_config import TelliotConfig


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
    parser.add_argument("--global-percentage-alert-threshold", type=float, help="Global percent threshold")
    parser.add_argument(
        "--global-percentage-warning-threshold", type=float, help="Global percentage for a warning dispute cat"
    )
    parser.add_argument("--global-percentage-minor-threshold", type=float, help="Global percentage for a minor dispute cat")
    parser.add_argument("--global-percentage-major-threshold", type=float, help="Global percentage for a major dispute cat")
    parser.add_argument("--global-range-alert-threshold", type=float, help="Global range threshold")
    parser.add_argument("--global-range-warning-threshold", type=float, help="Global range for a warning dispute cat")
    parser.add_argument("--global-range-minor-threshold", type=float, help="Global range for a minor dispute cat")
    parser.add_argument("--global-range-major-threshold", type=float, help="Global range for a major dispute cat")
    parser.add_argument("--global-equality-threshold", type=bool, help="Global equality threshold")
    args = parser.parse_args()

    if args.use_custom_config:
        global_percentage_alert_threshold = None
        global_percentage_warning_threshold = None
        global_percentage_minor_threshold = None
        global_percentage_major_threshold = None
        global_range_alert_threshold = None
        global_range_warning_threshold = None
        global_range_minor_threshold = None
        global_range_major_threshold = None
        global_equality_warning_threshold = None
        global_equality_minor_threshold = None
        global_equality_major_threshold = None
    else:
        if any(
            [
                not args.global_percentage_alert_threshold,
                not args.global_range_alert_threshold,
                not args.global_percentage_warning_threshold,
                not args.global_percentage_minor_threshold,
                not args.global_percentage_major_threshold,
                not args.global_range_warning_threshold,
                not args.global_range_minor_threshold,
                not args.global_range_major_threshold,
            ]
        ):
            raise ValueError("Global flags required if not using custom config")

        global_percentage_alert_threshold = args.global_percentage_alert_threshold
        global_range_alert_threshold = args.global_range_alert_threshold
        global_percentage_warning_threshold = args.global_percentage_warning_threshold
        global_percentage_minor_threshold = args.global_percentage_minor_threshold
        global_percentage_major_threshold = args.global_percentage_major_threshold
        global_range_alert_threshold = args.global_range_alert_threshold
        global_range_warning_threshold = args.global_range_warning_threshold
        global_range_minor_threshold = args.global_range_minor_threshold
        global_range_major_threshold = args.global_range_major_threshold
        global_equality_warning_threshold = args.global_equality_warning_threshold
        global_equality_minor_threshold = args.global_equality_minor_threshold
        global_equality_major_threshold = args.global_equality_major_threshold

    # Initialize config watcher
    config_path = Path(__file__).resolve().parents[2] / "config.toml"
    config_watcher = ConfigWatcher(config_path)

    reports_queue = asyncio.Queue()
    disputes_queue = asyncio.Queue()
    cfg = TelliotConfig()
    cfg.main.chain_id = 1

    # TODO: validate user options to check if they conflict
    try:
        await asyncio.gather(
            listen_to_new_report_events(uri, reports_queue),
            inspect_reports(
                reports_queue,
                disputes_queue,
                config_watcher,
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
            ),
            process_disputes(
                disputes_q=disputes_queue,
                binary_path=args.binary_path,
                key_name=args.key_name,
                kb=args.keyring_backend,
                kdir=args.keyring_dir,
                rpc=f"http://{uri}",
                chain_id=chain_id,
                payfrom_bond=args.payfrom_bond,
            ),
            watch_config(config_watcher),
        )
    except asyncio.CancelledError:
        print("shutting down running tasks")
        raise


if __name__ == "__main__":
    start()
