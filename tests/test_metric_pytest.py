from enum import Enum
from unittest.mock import patch

from layer_values_monitor.monitor import Metrics, get_metric

import pytest


class GlobalMetric(Enum):
    SPOTPRICE = "percentage"
    EVMCALL = "equality"


@pytest.fixture
def threshold_values():
    return {
        "percentage_alert": 0.9,
        "percentage_warning": 0.8,
        "percentage_minor": 0.7,
        "percentage_major": 0.6,
        "range_alert": 0.5,
        "range_warning": 0.4,
        "range_minor": 0.3,
        "range_major": 0.2,
        "equality_warning": 0.15,
        "equality_minor": 0.1,
        "equality_major": 0.05,
    }


def test_spotprice_returns_percentage_metric(threshold_values):
    result = get_metric(
        query_type="SPOTPRICE",
        global_percentage_alert_threshold=threshold_values["percentage_alert"],
        global_percentage_warning_threshold=threshold_values["percentage_warning"],
        global_percentage_minor_threshold=threshold_values["percentage_minor"],
        global_percentage_major_threshold=threshold_values["percentage_major"],
        global_range_alert_threshold=threshold_values["range_alert"],
        global_range_warning_threshold=threshold_values["range_warning"],
        global_range_minor_threshold=threshold_values["range_minor"],
        global_range_major_threshold=threshold_values["range_major"],
        global_equality_warning_threshold=threshold_values["equality_warning"],
        global_equality_minor_threshold=threshold_values["equality_minor"],
        global_equality_major_threshold=threshold_values["equality_major"],
    )

    expected = Metrics(
        metric="percentage",
        alert_threshold=threshold_values["percentage_alert"],
        warning_threshold=threshold_values["percentage_warning"],
        minor_threshold=threshold_values["percentage_minor"],
        major_threshold=threshold_values["percentage_major"],
    )

    assert result == expected


def test_evmcall_returns_equality_metric(threshold_values):
    """Test that EVMCALL query type returns equality metrics"""
    result = get_metric(
        query_type="EVMCALL",
        global_percentage_alert_threshold=threshold_values["percentage_alert"],
        global_percentage_warning_threshold=threshold_values["percentage_warning"],
        global_percentage_minor_threshold=threshold_values["percentage_minor"],
        global_percentage_major_threshold=threshold_values["percentage_major"],
        global_range_alert_threshold=threshold_values["range_alert"],
        global_range_warning_threshold=threshold_values["range_warning"],
        global_range_minor_threshold=threshold_values["range_minor"],
        global_range_major_threshold=threshold_values["range_major"],
        global_equality_warning_threshold=threshold_values["equality_warning"],
        global_equality_minor_threshold=threshold_values["equality_minor"],
        global_equality_major_threshold=threshold_values["equality_major"],
    )

    expected = Metrics(
        metric="equality",
        alert_threshold=1.0,  # Hardcoded in the function
        warning_threshold=threshold_values["equality_warning"],
        minor_threshold=threshold_values["equality_minor"],
        major_threshold=threshold_values["equality_major"],
    )

    assert result == expected


def test_invalid_query_type(threshold_values):
    with patch("layer_values_monitor.logger.logger.error") as mock_logger:
        result = get_metric(
            query_type="INVALID_TYPE",
            global_percentage_alert_threshold=threshold_values["percentage_alert"],
            global_percentage_warning_threshold=threshold_values["percentage_warning"],
            global_percentage_minor_threshold=threshold_values["percentage_minor"],
            global_percentage_major_threshold=threshold_values["percentage_major"],
            global_range_alert_threshold=threshold_values["range_alert"],
            global_range_warning_threshold=threshold_values["range_warning"],
            global_range_minor_threshold=threshold_values["range_minor"],
            global_range_major_threshold=threshold_values["range_major"],
            global_equality_warning_threshold=threshold_values["equality_warning"],
            global_equality_minor_threshold=threshold_values["equality_minor"],
            global_equality_major_threshold=threshold_values["equality_major"],
        )

        assert result is None
        mock_logger.assert_called_once_with("query type INVALID_TYPE not found in global metrics")


def test_case_insensitive_query_type(threshold_values):
    # Test with lowercase
    result_lower = get_metric(
        query_type="spotprice",
        global_percentage_alert_threshold=threshold_values["percentage_alert"],
        global_percentage_warning_threshold=threshold_values["percentage_warning"],
        global_percentage_minor_threshold=threshold_values["percentage_minor"],
        global_percentage_major_threshold=threshold_values["percentage_major"],
        global_range_alert_threshold=threshold_values["range_alert"],
        global_range_warning_threshold=threshold_values["range_warning"],
        global_range_minor_threshold=threshold_values["range_minor"],
        global_range_major_threshold=threshold_values["range_major"],
        global_equality_warning_threshold=threshold_values["equality_warning"],
        global_equality_minor_threshold=threshold_values["equality_minor"],
        global_equality_major_threshold=threshold_values["equality_major"],
    )

    # Test with uppercase
    result_upper = get_metric(
        query_type="SPOTPRICE",
        global_percentage_alert_threshold=threshold_values["percentage_alert"],
        global_percentage_warning_threshold=threshold_values["percentage_warning"],
        global_percentage_minor_threshold=threshold_values["percentage_minor"],
        global_percentage_major_threshold=threshold_values["percentage_major"],
        global_range_alert_threshold=threshold_values["range_alert"],
        global_range_warning_threshold=threshold_values["range_warning"],
        global_range_minor_threshold=threshold_values["range_minor"],
        global_range_major_threshold=threshold_values["range_major"],
        global_equality_warning_threshold=threshold_values["equality_warning"],
        global_equality_minor_threshold=threshold_values["equality_minor"],
        global_equality_major_threshold=threshold_values["equality_major"],
    )

    # Test with mixed case
    result_mixed = get_metric(
        query_type="SpOtPrIcE",
        global_percentage_alert_threshold=threshold_values["percentage_alert"],
        global_percentage_warning_threshold=threshold_values["percentage_warning"],
        global_percentage_minor_threshold=threshold_values["percentage_minor"],
        global_percentage_major_threshold=threshold_values["percentage_major"],
        global_range_alert_threshold=threshold_values["range_alert"],
        global_range_warning_threshold=threshold_values["range_warning"],
        global_range_minor_threshold=threshold_values["range_minor"],
        global_range_major_threshold=threshold_values["range_major"],
        global_equality_warning_threshold=threshold_values["equality_warning"],
        global_equality_minor_threshold=threshold_values["equality_minor"],
        global_equality_major_threshold=threshold_values["equality_major"],
    )

    assert result_lower == result_upper
    assert result_lower == result_mixed


def test_range_metric_not_in_enum(threshold_values):
    with patch("layer_values_monitor.logger.logger.error") as mock_logger:
        result = get_metric(
            query_type="RANGE",
            global_percentage_alert_threshold=threshold_values["percentage_alert"],
            global_percentage_warning_threshold=threshold_values["percentage_warning"],
            global_percentage_minor_threshold=threshold_values["percentage_minor"],
            global_percentage_major_threshold=threshold_values["percentage_major"],
            global_range_alert_threshold=threshold_values["range_alert"],
            global_range_warning_threshold=threshold_values["range_warning"],
            global_range_minor_threshold=threshold_values["range_minor"],
            global_range_major_threshold=threshold_values["range_major"],
            global_equality_warning_threshold=threshold_values["equality_warning"],
            global_equality_minor_threshold=threshold_values["equality_minor"],
            global_equality_major_threshold=threshold_values["equality_major"],
        )

        assert result is None
        mock_logger.assert_called_once_with("query type RANGE not found in global metrics")
