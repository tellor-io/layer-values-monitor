"""Type."""

from enum import Enum


class GlobalMetric(Enum):
    """Enumeration of global metrics with their associated measurement types."""

    SPOTPRICE = "percentage"
    EVMCALL = "equality"
