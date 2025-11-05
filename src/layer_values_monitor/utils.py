"""LVM helper functions."""

import logging
import os
from datetime import UTC, datetime

from layer_values_monitor.constants import CSV_FILE_PATTERN, CURRENT_CSV_FILE, LOGS_DIR, TABLE
from layer_values_monitor.custom_types import GlobalMetric, Metrics

import pandas as pd
from pandas import DataFrame

# Global counter to track current row count without reading file
_current_row_count = 0


def _get_max_table_rows() -> int:
    """Get MAX_TABLE_ROWS from environment, with default of 100000."""
    return int(os.getenv("MAX_TABLE_ROWS", "100000"))


def get_current_csv_path() -> str:
    """Get the full path to the current CSV file."""
    return os.path.join(LOGS_DIR, CURRENT_CSV_FILE)


def initialize_row_counter() -> None:
    """Initialize the row counter by counting existing rows in current CSV file."""
    global _current_row_count
    current_file = get_current_csv_path()

    if os.path.exists(current_file):
        try:
            # Only read the file once at startup to get current row count
            df = pd.read_csv(current_file)
            _current_row_count = len(df)
            logging.info(f"Initialized row counter: {_current_row_count} rows in current CSV file")
        except Exception as e:
            logging.error(f"Error initializing row counter: {e}")
            _current_row_count = 0
    else:
        _current_row_count = 0


def should_create_new_file() -> bool:
    """Check if we should create a new file based on row count."""
    current_file = get_current_csv_path()
    if not os.path.exists(current_file):
        return True

    try:
        # Read the CSV file and count rows (excluding header)
        df = pd.read_csv(current_file)
        return len(df) >= _get_max_table_rows()
    except Exception as e:
        logging.error(f"Error checking file size: {e}")
        return False


def create_new_csv_file() -> str:
    """Create a new CSV file with current timestamp and return its path."""
    global _current_row_count
    timestamp = int(datetime.now(UTC).timestamp())
    new_filename = CSV_FILE_PATTERN.format(timestamp=timestamp)
    new_filepath = os.path.join(LOGS_DIR, new_filename)

    # Update the current CSV file constant
    global CURRENT_CSV_FILE
    CURRENT_CSV_FILE = new_filename

    # Reset row counter for new file
    _current_row_count = 0

    return new_filepath


def remove_0x_prefix(s: str) -> str:
    """Remove 0x prefix if there from hex string."""
    if s.startswith("0x"):
        return s[2:]
    return s


def decode_hex_value(hex_value: str) -> float:
    """Decode a hex value to a readable number."""
    # Remove 0x prefix if present
    if hex_value.startswith("0x"):
        hex_value = hex_value[2:]

    # Validate hex value length - oracle values should be 32 bytes (64 hex chars)
    if len(hex_value) > 64:
        raise ValueError(f"Hex value too long ({len(hex_value)} chars) - expected ≤64 chars: {hex_value[:100]}...")

    # Convert from hex to int
    value_int = int(hex_value, 16)

    value_scaled = value_int / (10**18)

    return value_scaled


def add_to_table(entry: dict[str, str]) -> None:
    """Add entry to table and save to CSV (without console output)."""
    global _current_row_count
    TABLE.append(entry)
    _current_row_count += 1

    # Only check file size every 1000 entries or when approaching limit
    # This eliminates the expensive file reading on every single report
    if _current_row_count % 1000 == 0 or _current_row_count >= _get_max_table_rows():
        if should_create_new_file():
            csv_file = create_new_csv_file()
            # Create new file with header
            DataFrame([entry]).to_csv(csv_file, mode="w", header=True, index=False)
            _current_row_count = 1  # Reset counter for new file
        else:
            csv_file = get_current_csv_path()
            # Append to existing file
            DataFrame([entry]).to_csv(csv_file, mode="a", header=False, index=False)
    else:
        # Just append without checking - much faster
        csv_file = get_current_csv_path()
        DataFrame([entry]).to_csv(csv_file, mode="a", header=False, index=False)
