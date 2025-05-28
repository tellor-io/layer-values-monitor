"""LVM helper functions."""

import logging
import os
from datetime import datetime, timezone
import pandas as pd
from dotenv import load_dotenv

from layer_values_monitor.constants import TABLE, CSV_FILE_PATTERN, CURRENT_CSV_FILE, LOGS_DIR
from layer_values_monitor.custom_types import GlobalMetric, Metrics
from layer_values_monitor.threshold_config import ThresholdConfig

from pandas import DataFrame

# Load environment variables
load_dotenv()
MAX_TABLE_ROWS = int(os.getenv("MAX_TABLE_ROWS", "1000"))  # Default to 1000 if not set

def get_current_csv_path() -> str:
    """Get the full path to the current CSV file."""
    return os.path.join(LOGS_DIR, CURRENT_CSV_FILE)

def should_create_new_file() -> bool:
    """Check if we should create a new file based on row count."""
    current_file = get_current_csv_path()
    if not os.path.exists(current_file):
        return True
    
    try:
        # Read the CSV file and count rows (excluding header)
        df = pd.read_csv(current_file)
        return len(df) >= MAX_TABLE_ROWS
    except Exception as e:
        logging.error(f"Error checking file size: {e}")
        return False

def create_new_csv_file() -> str:
    """Create a new CSV file with current timestamp and return its path."""
    timestamp = int(datetime.now(timezone.utc).timestamp())
    new_filename = CSV_FILE_PATTERN.format(timestamp=timestamp)
    new_filepath = os.path.join(LOGS_DIR, new_filename)
    
    # Update the current CSV file constant
    global CURRENT_CSV_FILE
    CURRENT_CSV_FILE = new_filename
    
    return new_filepath

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
    df = DataFrame(TABLE).sort_values(by="TIMESTAMP")
    print(df.to_string(index=False, justify="center"))

    # Check if we need to create a new file
    if should_create_new_file():
        csv_file = create_new_csv_file()
        # Create new file with header
        DataFrame([entry]).to_csv(csv_file, mode="w", header=True, index=False)
    else:
        csv_file = get_current_csv_path()
        # Append to existing file
        DataFrame([entry]).to_csv(csv_file, mode="a", header=False, index=False)
