"""Per-query alert condition state tracking to suppress repeated Discord alerts."""

import time
from typing import Any


class AlertStateTracker:
    """Track which query IDs are in an active alert condition.

    When a query first becomes alertable (reported value diverges from trusted value),
    one Discord alert is sent and the query is marked active. While the condition
    persists, further per-reporter alerts for the same query are suppressed.
    When the condition clears (diff drops below threshold), a single
    'Alert Condition Resolved' message is sent.

    All methods are synchronous because they only touch an in-memory dict and are
    called without intervening ``await`` points, making them effectively atomic
    under the asyncio single-threaded event loop.
    """

    def __init__(self) -> None:
        """Initialize empty active alert tracking state."""
        self._active: dict[str, dict[str, Any]] = {}
        # {query_id: {"first_seen": float, "last_seen": float,
        #             "suppressed_count": int, "last_diff": float,
        #             "query_info": str}}

    def should_alert(self, query_id: str) -> bool:
        """Return True if no alert has been sent yet for this query_id's current condition.

        Returns False when the condition is already tracked as active, meaning the
        alert has already fired and further per-reporter alerts should be suppressed.
        """
        return query_id not in self._active

    def mark_active(self, query_id: str, diff: float, query_info: str = "") -> None:
        """Record that an alert was sent for query_id and the condition is now active."""
        if query_id in self._active:
            # Already active - update tracking metadata without re-alerting
            self._active[query_id]["last_seen"] = time.time()
            self._active[query_id]["suppressed_count"] += 1
            self._active[query_id]["last_diff"] = diff
        else:
            now = time.time()
            self._active[query_id] = {
                "first_seen": now,
                "last_seen": now,
                "suppressed_count": 0,
                "last_diff": diff,
                "query_info": query_info,
            }

    def record_suppressed(self, query_id: str, diff: float) -> None:
        """Update tracking metadata for a suppressed alert (condition still active)."""
        state = self._active.get(query_id)
        if state is not None:
            state["last_seen"] = time.time()
            state["suppressed_count"] += 1
            state["last_diff"] = diff

    def check_resolved(self, query_id: str) -> bool:
        """Return True if the condition was previously active but is now cleared.

        Call this on the non-alertable path to detect when to send a recovery message.
        """
        return query_id in self._active

    def mark_resolved(self, query_id: str) -> None:
        """Remove query_id from active tracking after a recovery alert is sent."""
        self._active.pop(query_id, None)

    def get_active_state(self, query_id: str) -> dict[str, Any] | None:
        """Return the tracked state dict for an active condition (for recovery messages)."""
        return self._active.get(query_id)

    def is_active(self, query_id: str) -> bool:
        """Return True if query_id currently has an active alert condition."""
        return query_id in self._active

    def clear(self) -> None:
        """Remove all active alert tracking state."""
        self._active.clear()


_alert_state_tracker = AlertStateTracker()


def get_alert_state_tracker() -> AlertStateTracker:
    """Return the global singleton AlertStateTracker."""
    return _alert_state_tracker
