import logging
from unittest.mock import MagicMock, patch

from layer_values_monitor.threshold_config import ThresholdConfig
from layer_values_monitor.utils import Metrics, get_metric

import pytest

mock_logger = MagicMock(spec=logging.Logger)


@pytest.fixture
def threshold_values():
    return ThresholdConfig(
        percentage_alert=0.9,
        percentage_warning=0.8,
        percentage_minor=0.7,
        percentage_major=0.6,
        range_alert=0.5,
        range_warning=0.4,
        range_minor=0.3,
        range_major=0.2,
        equality_alert=1.0,
        equality_warning=1.0,
        equality_minor=1.0,
        equality_major=0.0,
    )


def test_spotprice_returns_percentage_metric(threshold_values):
    result = get_metric(query_type="SPOTPRICE", logger=mock_logger, threshold_config=threshold_values)

    expected = Metrics(
        metric="percentage",
        alert_threshold=threshold_values.percentage_alert,
        warning_threshold=threshold_values.percentage_warning,
        minor_threshold=threshold_values.percentage_minor,
        major_threshold=threshold_values.percentage_major,
    )

    assert result == expected


def test_evmcall_returns_equality_metric(threshold_values):
    """Test that EVMCALL query type returns equality metrics"""
    result = get_metric(query_type="EVMCALL", logger=mock_logger, threshold_config=threshold_values)

    expected = Metrics(
        metric="equality",
        alert_threshold=1.0,  # Hardcoded in the function
        warning_threshold=threshold_values.equality_warning,
        minor_threshold=threshold_values.equality_minor,
        major_threshold=threshold_values.equality_major,
    )

    assert result == expected


def test_invalid_query_type(threshold_values):
    with patch("layer_values_monitor.logger.logger.error") as patched_logger:
        mock_logger.error = patched_logger
        result = get_metric(query_type="INVALID_TYPE", logger=mock_logger, threshold_config=threshold_values)

        assert result is None
        patched_logger.assert_called_once_with("query type INVALID_TYPE not found in global metrics")


def test_case_insensitive_query_type(threshold_values):
    # Test with lowercase
    result_lower = get_metric(query_type="spotprice", logger=mock_logger, threshold_config=threshold_values)

    # Test with uppercase
    result_upper = get_metric(query_type="SPOTPRICE", logger=mock_logger, threshold_config=threshold_values)

    # Test with mixed case
    result_mixed = get_metric(query_type="SpOtPrIcE", logger=mock_logger, threshold_config=threshold_values)

    assert result_lower == result_upper
    assert result_lower == result_mixed


def test_range_metric_not_in_enum(threshold_values):
    with patch("layer_values_monitor.logger.logger.error") as patched_logger:
        mock_logger.error = patched_logger
        result = get_metric(query_type="RANGE", logger=mock_logger, threshold_config=threshold_values)

        assert result is None
        patched_logger.assert_called_once_with("query type RANGE not found in global metrics")
