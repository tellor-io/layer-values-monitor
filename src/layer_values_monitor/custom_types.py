"""Type."""

from dataclasses import dataclass
from enum import Enum
from typing import Literal

DisputeCategory = Literal["warning", "minor", "major"]


class GlobalMetric(Enum):
    """Enumeration of global metrics with their associated measurement types."""

    SPOTPRICE = "percentage"
    EVMCALL = "equality"


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
