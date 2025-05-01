"""LVM helper functions."""

import logging
import os

from layer_values_monitor.constants import CSV_FILE, TABLE
from layer_values_monitor.custom_types import GlobalMetric, Metrics
from layer_values_monitor.threshold_config import ThresholdConfig

from pandas import DataFrame


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

    if os.path.exists(CSV_FILE):
        # if file exists then just append to it
        DataFrame([entry]).to_csv(CSV_FILE, mode="a", header=False, index=False)
    else:
        # else create file and add header
        DataFrame([entry]).to_csv(CSV_FILE, mode="w", header=True, index=False)
