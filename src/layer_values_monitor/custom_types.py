"""Type."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal

DisputeCategory = Literal["warning", "minor", "major"]


class GlobalMetric(Enum):
    """Enumeration of global metrics with their associated measurement types."""

    SPOTPRICE = "percentage"
    EVMCALL = "equality"
    TRBBRIDGE = "equality"


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
    pause_threshold: float


@dataclass
class PowerThresholds:
    """Define power-based thresholds for Saga pausing logic."""

    immediate_pause_threshold: float = 0.66  # >66% can pause immediately
    delayed_pause_threshold: float = 0.33    # >33% can pause after delay
    
    # Delay hours is fixed at 12 hours (not configurable)
    @property
    def pause_delay_hours(self) -> int:
        """Fixed 12-hour delay for delayed pauses."""
        return 12


@dataclass
class PendingPause:
    """Store information about a pending pause for delayed power thresholds."""
    
    query_id: str
    contract_address: str
    trigger_time: float
    power_info: dict[str, Any]
    agg_report: AggregateReport
    reason: str


@dataclass
class Reporter:
    """Store information about a reporter."""

    address: str
    power: int
    jailed: bool
    moniker: str | None = None


@dataclass
class ReporterQueryResponse:
    """Store the response from querying all reporters."""

    reporters: list[Reporter]
    total_non_jailed_power: int


@dataclass
class AggregateReport:
    """Store information about an aggregate report event."""

    query_id: str
    query_data: str
    value: str
    aggregate_power: str
    micro_report_height: str
    height: int | None = None
