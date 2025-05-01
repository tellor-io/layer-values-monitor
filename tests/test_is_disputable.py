import logging
from unittest.mock import MagicMock, patch

from layer_values_monitor.monitor import is_disputable

import pytest

magic_logger = MagicMock(spec=logging.Logger)


@pytest.mark.parametrize(
    "reported_value,trusted_value,alert_threshold,dispute_threshold,expected",
    [
        # Case: Percent difference exactly at alert threshold
        (110, 100, 0.1, 0.2, (True, False, 0.1)),
        # Case: Percent difference below alert threshold
        (105, 100, 0.1, 0.2, (False, False, 0.05)),
        # Case: Percent difference above alert threshold but below dispute threshold
        (115, 100, 0.1, 0.2, (True, False, 0.15)),
        # Case: Percent difference above both thresholds
        (125, 100, 0.1, 0.2, (True, True, 0.25)),
        # Case: Negative percent difference (reported < trusted)
        (80, 100, 0.1, 0.2, (True, True, 0.2)),
        # Case: dispute_threshold = 0 (special handling)
        (115, 100, 0.1, 0, (True, False, 0.15)),
    ],
)
def test_percentage_metric(reported_value, trusted_value, alert_threshold, dispute_threshold, expected):
    """Test percentage metric calculations and threshold checks."""
    with patch("layer_values_monitor.logger.logger.debug") as mock_logger:
        magic_logger.debug = mock_logger
        result = is_disputable("percentage", alert_threshold, dispute_threshold, reported_value, trusted_value, magic_logger)
        # logger.debug was called?
        mock_logger.assert_called_once()

        assert result[0] == expected[0]
        assert result[1] == expected[1]
        assert abs(result[2] - expected[2]) < 1e-10


@pytest.mark.parametrize(
    "reported_value,trusted_value,expected",
    [
        # Case: Values are equal (hex)
        ("0x123abc", "0x123abc", (False, False, 0.0)),
        # Case: Values are equal (different case)
        ("0x123ABC", "0x123abc", (False, False, 0.0)),
        # Case: Values are equal (one with prefix, one without)
        ("0x123abc", "123abc", (False, False, 0.0)),
        # Case: Values are not equal
        ("0x123abc", "0x456def", (True, True, 1.0)),
        (123, "123", (False, False, 0.0)),
        # Case: One value is None
        (None, "123abc", (True, True, 1.0)),
    ],
)
def test_equality_metric(reported_value, trusted_value, expected):
    """Test equality metric comparisons."""
    with patch("layer_values_monitor.logger.logger.info") as mock_logger:
        magic_logger.info = mock_logger
        result = is_disputable("equality", 0.1, 0.2, reported_value, trusted_value, magic_logger)

        mock_logger.assert_called_once()

        assert result == expected


@pytest.mark.parametrize(
    "reported_value,trusted_value,alert_threshold,dispute_threshold,expected",
    [
        # Case: Difference exactly at alert threshold
        (110, 100, 10, 20, (True, False, 10)),
        # Case: Difference below alert threshold
        (105, 100, 10, 20, (False, False, 5)),
        # Case: Difference above alert threshold but below dispute threshold
        (115, 100, 10, 20, (True, False, 15)),
        # Case: Difference above both thresholds
        (125, 100, 10, 20, (True, True, 25)),
        # Case: Negative difference (reported < trusted)
        (80, 100, 10, 20, (True, True, 20)),
        # Case: Reported and trusted are equal
        (100, 100, 10, 20, (False, False, 0)),
    ],
)
def test_range_metric(reported_value, trusted_value, alert_threshold, dispute_threshold, expected):
    """Test range metric calculations and threshold checks."""
    with patch("layer_values_monitor.logger") as mock_logger:
        result = is_disputable("range", alert_threshold, dispute_threshold, reported_value, trusted_value, mock_logger)

        # Range metric doesn't log anything specific
        mock_logger.debug.assert_not_called()
        mock_logger.info.assert_not_called()

        # Verify results
        assert result[0] == expected[0]
        assert result[1] == expected[1]
        assert result[2] == expected[2]


@pytest.mark.parametrize(
    "metric,case_variant",
    [
        ("percentage", "PERCENTAGE"),
        ("equality", "EqUaLiTy"),
        ("range", "Range"),
    ],
)
def test_case_insensitivity(metric, case_variant):
    """Test that metric string comparison is case-insensitive."""
    # Use simple values where results will be the same for all metrics
    result_lower = is_disputable(metric, 1, 1, 100, 100, magic_logger)
    result_variant = is_disputable(case_variant, 1, 1, 100, 100, magic_logger)

    assert result_lower == result_variant


def test_unknown_metric():
    """Test behavior with an unknown metric type."""
    result = is_disputable("unknown_metric", 0.1, 0.2, 100, 100, magic_logger)
    assert result[0] is None
