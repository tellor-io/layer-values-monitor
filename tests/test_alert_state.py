"""Tests for Discord alert condition state tracking."""

from layer_values_monitor.alert_state import AlertStateTracker


def test_alert_state_alerts_once_until_resolved():
    """A query alerts once while active and can alert again after resolution."""
    tracker = AlertStateTracker()
    query_id = "query_1"

    assert tracker.should_alert(query_id) is True

    tracker.mark_active(query_id, 0.15, "ETH/USD")
    assert tracker.should_alert(query_id) is False
    assert tracker.check_resolved(query_id) is True

    tracker.mark_resolved(query_id)
    assert tracker.should_alert(query_id) is True


def test_alert_state_counts_suppressed_alerts():
    """Suppressed repeats update metadata for the eventual resolved message."""
    tracker = AlertStateTracker()
    query_id = "query_2"

    tracker.mark_active(query_id, 0.1, "BTC/USD")
    tracker.record_suppressed(query_id, 0.2)
    tracker.record_suppressed(query_id, 0.3)

    state = tracker.get_active_state(query_id)

    assert state is not None
    assert state["suppressed_count"] == 2
    assert state["last_diff"] == 0.3
