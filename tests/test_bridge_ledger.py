"""Tests for the bridge deposit ledger (SQLite journal)."""

import time

from layer_values_monitor.bridge_ledger import (
    STATUS_MISMATCH_PENDING,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED_OK,
    BridgeLedger,
)

import pytest

CONTRACT = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
REPORTED = {"eth_address": "0xabc", "layer_address": "tellor1x", "amount": 100, "tip": 1}


@pytest.fixture
def ledger(tmp_path):
    led = BridgeLedger(str(tmp_path / "bridge_ledger.db"))
    yield led
    led.close()


def insert(ledger, tx_hash="0xtx1", status=STATUS_UNVERIFIED, report_ts=None, deposit_id=7):
    return ledger.upsert_report(
        tx_hash=tx_hash,
        query_id="0xq",
        query_type="TRBBridge",
        deposit_id=deposit_id,
        reported_value=REPORTED,
        status=status,
        report_ts=report_ts or time.time(),
        contract_address=CONTRACT,
        reporter="tellor1rep",
        power="1000",
        meta_id="42",
    )


class TestBridgeDeposits:
    def test_roundtrip_insert_and_get(self, ledger):
        assert insert(ledger) is True
        row = ledger.get("0xtx1")
        assert row["status"] == STATUS_UNVERIFIED
        assert row["deposit_id"] == 7
        assert row["meta_id"] == "42"
        import json

        assert json.loads(row["reported_json"]) == REPORTED

    def test_upsert_is_idempotent_by_tx_hash(self, ledger):
        """Catch-up replay of the same report must not reset an advanced status."""
        assert insert(ledger, status=STATUS_UNVERIFIED) is True
        ledger.set_status("0xtx1", STATUS_MISMATCH_PENDING)
        assert insert(ledger, status=STATUS_VERIFIED_OK) is False
        assert ledger.get("0xtx1")["status"] == STATUS_MISMATCH_PENDING

    def test_set_status_transitions_and_retries(self, ledger):
        insert(ledger)
        ledger.set_status("0xtx1", STATUS_MISMATCH_PENDING, error="tier1_mismatch")
        row = ledger.get("0xtx1")
        assert row["status"] == STATUS_MISMATCH_PENDING
        assert row["last_error"] == "tier1_mismatch"
        assert row["retries"] == 0

        ledger.set_status("0xtx1", STATUS_MISMATCH_PENDING, bump_retries=True)
        assert ledger.get("0xtx1")["retries"] == 1

    def test_due_for_recheck(self, ledger):
        insert(ledger, tx_hash="0xa", status=STATUS_UNVERIFIED)
        insert(ledger, tx_hash="0xb", status=STATUS_VERIFIED_OK)
        insert(ledger, tx_hash="0xc", status=STATUS_MISMATCH_PENDING)

        now = time.time()
        # state_ts is 'now' → nothing due within the interval
        assert [r["tx_hash"] for r in ledger.due_for_recheck(now=now, interval=600)] == []

        # One hour later, only the non-terminal rows are due
        due = {r["tx_hash"] for r in ledger.due_for_recheck(now=now + 3600, interval=600)}
        assert due == {"0xa", "0xc"}

    def test_near_deadline_and_escalation(self, ledger):
        old = time.time() - 10.5 * 3600  # past the 10h escalation point, before the 12h deadline
        insert(ledger, tx_hash="0xa", status=STATUS_MISMATCH_PENDING, report_ts=old)
        insert(ledger, tx_hash="0b", status=STATUS_VERIFIED_OK, report_ts=old)

        rows = ledger.near_deadline(now=time.time(), hours=12, margin=2)
        assert [r["tx_hash"] for r in rows] == ["0xa"]

        ledger.mark_escalated("0xa")
        assert ledger.near_deadline(now=time.time(), hours=12, margin=2) == []

    def test_expired(self, ledger):
        insert(ledger, tx_hash="0xa", status=STATUS_UNVERIFIED, report_ts=time.time() - 12.5 * 3600)
        insert(ledger, tx_hash="0b", status=STATUS_UNVERIFIED, report_ts=time.time() - 11.5 * 3600)
        expired = ledger.expired(now=time.time(), hours=12)
        assert [r["tx_hash"] for r in expired] == ["0xa"]

    def test_persistence_across_reopen(self, tmp_path):
        path = str(tmp_path / "reopen.db")
        led = BridgeLedger(path)
        insert(led, tx_hash="0xpersist")
        led.set_status("0xpersist", STATUS_MISMATCH_PENDING)
        led.close()

        led2 = BridgeLedger(path)
        row = led2.get("0xpersist")
        assert row is not None
        assert row["status"] == STATUS_MISMATCH_PENDING
        led2.close()


class TestEthDeposits:
    def test_record_and_duplicate(self, ledger):
        assert ledger.record_eth_deposit(CONTRACT, 7, "0xeth", 100, REPORTED) is True
        assert ledger.record_eth_deposit(CONTRACT, 7, "0xeth", 100, REPORTED) is False
        assert ledger.has_eth_deposit(CONTRACT, 7) is True
        assert ledger.has_eth_deposit(CONTRACT, 8) is False

    def test_pending_missing_reports_and_alert_once(self, ledger):
        insert(ledger, tx_hash="0xtx1", status=STATUS_VERIFIED_OK, deposit_id=7)
        ledger.record_eth_deposit(CONTRACT, 7, "0xethA", 100)
        ledger.record_eth_deposit(CONTRACT, 8, "0xethB", 200)

        now = time.time()
        # reporting window still open; nothing pending yet
        assert ledger.pending_missing_reports(now=now, window_s=3600) == []

        # Two hours later, deposit 8 (no Layer report) is pending; deposit 7 is covered
        pending = ledger.pending_missing_reports(now=now + 7200, window_s=3600)
        assert [r["deposit_id"] for r in pending] == [8]

        assert ledger.mark_missing_report(CONTRACT, 8) is True
        assert ledger.mark_missing_report(CONTRACT, 8) is False  # alert-once
        assert ledger.pending_missing_reports(now=now + 7200, window_s=3600) == []

    def test_missing_window_anchored_on_block_ts(self, ledger):
        """A deposit swept long after it happened must not be 'pending' until ITS window closes."""
        now = time.time()
        ledger.record_eth_deposit(CONTRACT, 9, "0xethC", 300, block_ts=now)
        ledger.conn.execute("UPDATE eth_deposits SET first_seen_ts=? WHERE deposit_id=9", (now - 86_400,))
        ledger.conn.commit()
        # first_seen is a day old, but the deposit itself just happened: window open
        assert ledger.pending_missing_reports(now=now + 1800, window_s=3600) == []
        pending = ledger.pending_missing_reports(now=now + 7200, window_s=3600)
        assert [r["deposit_id"] for r in pending] == [9]

    def test_rows_without_log(self, ledger):
        insert(ledger, tx_hash="0xtx1", status=STATUS_MISMATCH_PENDING, deposit_id=7)
        insert(ledger, tx_hash="0xtx2", status=STATUS_MISMATCH_PENDING, deposit_id=8)
        ledger.record_eth_deposit(CONTRACT, 7, "0xethA", 100)

        # Sweep covers everything from 'start_ts' (0) onward; reports are past the grace
        rows = ledger.rows_without_log(CONTRACT, sweep_covered_from_ts=0, now=time.time() + 7200)
        assert [r["tx_hash"] for r in rows] == ["0xtx2"]

        # Within the no-log grace (sweep lags finalized), a missing log proves nothing yet
        assert ledger.rows_without_log(CONTRACT, sweep_covered_from_ts=0) == []

        # A sweep that started AFTER the report covers nothing relevant
        assert ledger.rows_without_log(CONTRACT, sweep_covered_from_ts=time.time() + 10, now=time.time() + 7200) == []


class TestMeta:
    def test_meta_roundtrip(self, ledger):
        assert ledger.get_meta("cursor") is None
        assert ledger.get_meta("cursor", "0") == "0"
        ledger.set_meta("cursor", "123")
        assert ledger.get_meta("cursor") == "123"
        ledger.set_meta("cursor", "456")
        assert ledger.get_meta("cursor") == "456"
