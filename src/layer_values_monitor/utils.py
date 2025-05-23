"""LVM helper functions."""

import logging
import os
from datetime import datetime, timezone

from layer_values_monitor.constants import TABLE,CSV_FILE_PATTERN
from layer_values_monitor.custom_types import GlobalMetric, Metrics
from layer_values_monitor.threshold_config import ThresholdConfig

from pandas import DataFrame


logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs")


def get_metric(
    query_type: str,
    logger: logging,
    threshold_config: ThresholdConfig,
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
            alert_threshold=threshold_config.percentage_alert,
            warning_threshold=threshold_config.percentage_warning,
            minor_threshold=threshold_config.percentage_minor,
            major_threshold=threshold_config.percentage_major,
        )
    elif metric == "range":
        return Metrics(
            metric=metric,
            alert_threshold=threshold_config.range_alert,
            warning_threshold=threshold_config.range_warning,
            minor_threshold=threshold_config.range_minor,
            major_threshold=threshold_config.range_major,
        )
    elif metric == "equality":
        return Metrics(
            metric=metric,
            alert_threshold=threshold_config.equality_alert,
            warning_threshold=threshold_config.equality_warning,
            minor_threshold=threshold_config.equality_minor,
            major_threshold=threshold_config.equality_major,
        )


def remove_0x_prefix(s: str) -> str:
    """Remove 0x prefix if there from hex string."""
    if s.startswith("0x"):
        return s[2:]
    return s


def add_to_table(entry: dict[str, str]) -> None:
    """Add entry to table and print it."""
    TABLE.append(entry)
    os.system("clear")
    # df = pd.DataFrame(table)
    df = DataFrame(TABLE).sort_values(by="TIMESTAMP")
    print(df.to_string(index=False, justify="center"))

    # Get the current day's CSV file
    current_csv_file = get_current_csv_file()
    
    # Check if we need to switch to a new file (if current time is past midnight UTC)
    current_time = datetime.now(timezone.utc)
    file_timestamp = int(os.path.basename(current_csv_file).split("_")[1].split(".")[0])
    file_date = datetime.fromtimestamp(file_timestamp, timezone.utc)
    
    if current_time.date() > file_date.date():
        # We're in a new day, use the new file
        csv_file = current_csv_file
    else:
        # Try to get the latest existing file, or use current day's file if none exists
        csv_file = get_latest_csv_file() or current_csv_file

    # Write to the appropriate CSV file
    if os.path.exists(csv_file):
        # if file exists then just append to it
        DataFrame([entry]).to_csv(csv_file, mode="a", header=False, index=False)
    else:
        # else create file and add header
        DataFrame([entry]).to_csv(csv_file, mode="w", header=True, index=False)

def get_current_csv_file() -> str:
    """Get the current day's CSV file path based on UTC timestamp."""
    current_time = datetime.now(timezone.utc)
    # Get the start of the current UTC day
    day_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
    timestamp = int(day_start.timestamp())
    return os.path.join(logs_dir, CSV_FILE_PATTERN.format(timestamp=timestamp))

def get_latest_csv_file() -> str | None:
    """Get the most recent CSV file from the logs directory."""
    csv_files = [f for f in os.listdir(logs_dir) if f.startswith("table_") and f.endswith(".csv")]
    if not csv_files:
        return None
    # Sort by timestamp in filename and get the most recent
    latest_file = sorted(csv_files, key=lambda x: int(x.split("_")[1].split(".")[0]))[-1]
    return os.path.join(logs_dir, latest_file)
