"""Tests for the bridge deposit ledger (SQLite journal)."""

import sqlite3
import time

from layer_values_monitor.bridge_ledger import (
    STATUS_BAD,
    STATUS_GOOD,
    STATUS_UNVERIFIED,
    TERMINAL_STATUSES,
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
        ledger.set_status("0xtx1", STATUS_BAD)
        assert insert(ledger, status=STATUS_GOOD) is False
        assert ledger.get("0xtx1")["status"] == STATUS_BAD

    def test_set_status_transitions_and_retries(self, ledger):
        insert(ledger)
        ledger.set_status("0xtx1", STATUS_UNVERIFIED, error="rpc_error")
        row = ledger.get("0xtx1")
        assert row["status"] == STATUS_UNVERIFIED
        assert row["last_error"] == "rpc_error"
        assert row["retries"] == 0

        ledger.set_status("0xtx1", STATUS_UNVERIFIED, bump_retries=True)
        assert ledger.get("0xtx1")["retries"] == 1

    def test_due_for_recheck_only_unverified(self, ledger):
        insert(ledger, tx_hash="0xa", status=STATUS_UNVERIFIED)
        insert(ledger, tx_hash="0xb", status=STATUS_GOOD)
        insert(ledger, tx_hash="0xc", status=STATUS_BAD)

        now = time.time()
        # state_ts is 'now' → nothing due within the interval
        assert [r["tx_hash"] for r in ledger.due_for_recheck(now=now, interval=600)] == []

        # One hour later, only the unverified row is due — good/bad are the only terminals
        due = {r["tx_hash"] for r in ledger.due_for_recheck(now=now + 3600, interval=600)}
        assert due == {"0xa"}
        assert TERMINAL_STATUSES == {STATUS_GOOD, STATUS_BAD}

    def test_retry_forever_no_cap(self, ledger):
        """A row retried 100 times must still come back: no retry cap, no expiry."""
        insert(ledger, tx_hash="0xa", status=STATUS_UNVERIFIED, report_ts=time.time() - 30 * 86_400)
        ledger.conn.execute("UPDATE bridge_deposits SET retries = 100 WHERE tx_hash = '0xa'")
        ledger.conn.commit()
        due = ledger.due_for_recheck(now=time.time() + 3600, interval=600)
        assert [r["tx_hash"] for r in due] == ["0xa"]
        assert due[0]["retries"] == 100

    def test_near_deadline_and_escalation(self, ledger):
        old = time.time() - 10.5 * 3600  # past the 10h escalation point, before the 12h deadline
        insert(ledger, tx_hash="0xa", status=STATUS_UNVERIFIED, report_ts=old)
        insert(ledger, tx_hash="0b", status=STATUS_GOOD, report_ts=old)

        rows = ledger.near_deadline(now=time.time(), hours=12, margin=2)
        assert [r["tx_hash"] for r in rows] == ["0xa"]

        ledger.mark_escalated("0xa")
        assert ledger.near_deadline(now=time.time(), hours=12, margin=2) == []

    def test_persistence_across_reopen(self, tmp_path):
        path = str(tmp_path / "reopen.db")
        led = BridgeLedger(path)
        insert(led, tx_hash="0xpersist")
        led.set_status("0xpersist", STATUS_BAD)
        led.close()

        led2 = BridgeLedger(path)
        row = led2.get("0xpersist")
        assert row is not None
        assert row["status"] == STATUS_BAD
        led2.close()


class TestStatusMigration:
    """One-time migration of the pre-three-status vocabulary, run on every ledger open."""

    @pytest.mark.parametrize(
        "old_status,new_status",
        [
            ("verified_ok", "good"),
            ("resolved_lag", "good"),
            ("disputed", "bad"),
            ("unverifiable", "unverified"),
            ("expired_unresolved", "unverified"),
        ],
    )
    def test_old_statuses_map_on_reopen(self, tmp_path, old_status, new_status):
        path = str(tmp_path / f"mig_{old_status}.db")
        led = BridgeLedger(path)
        insert(led, tx_hash="0xmig")
        # simulate a row written by pre-migration code
        led.conn.execute("UPDATE bridge_deposits SET status = ? WHERE tx_hash = '0xmig'", (old_status,))
        led.conn.commit()
        led.close()

        led2 = BridgeLedger(path)
        assert led2.get("0xmig")["status"] == new_status
        led2.close()

    def test_migration_is_idempotent(self, tmp_path):
        path = str(tmp_path / "mig2.db")
        led = BridgeLedger(path)
        insert(led, tx_hash="0xmig", status=STATUS_GOOD)
        insert(led, tx_hash="0x2", status=STATUS_UNVERIFIED)
        led.close()

        BridgeLedger(path).close()
        led3 = BridgeLedger(path)  # reopens must leave new statuses untouched
        assert led3.get("0xmig")["status"] == "good"
        assert led3.get("0x2")["status"] == "unverified"
        led3.close()

    def test_stranded_unverifiable_resumes_retrying(self, tmp_path):
        """The original complaint: rows stranded in unverifiable must re-enter the retry loop."""
        path = str(tmp_path / "mig3.db")
        led = BridgeLedger(path)
        insert(led, tx_hash="0xstranded", status=STATUS_UNVERIFIED)
        led.conn.execute("UPDATE bridge_deposits SET status = 'unverifiable' WHERE tx_hash = '0xstranded'")
        led.conn.commit()
        led.close()

        led2 = BridgeLedger(path)
        due = led2.due_for_recheck(now=time.time() + 3600, interval=600)
        assert [r["tx_hash"] for r in due] == ["0xstranded"]
        led2.close()


class TestLegacySideTablesDropped:
    """Opening an older ledger drops the sweep tables and keeps the report rows."""

    def test_eth_deposits_and_meta_removed(self, tmp_path):
        path = str(tmp_path / "old.db")
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE bridge_deposits (
                tx_hash TEXT PRIMARY KEY,
                query_id TEXT NOT NULL,
                query_type TEXT NOT NULL,
                contract_address TEXT,
                deposit_id INTEGER,
                reported_json TEXT,
                status TEXT NOT NULL,
                state_ts REAL NOT NULL,
                report_ts REAL NOT NULL,
                retries INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                reporter TEXT,
                power TEXT,
                meta_id TEXT,
                escalated INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE eth_deposits (
                contract_address TEXT NOT NULL,
                deposit_id INTEGER NOT NULL,
                first_seen_ts REAL NOT NULL,
                PRIMARY KEY (contract_address, deposit_id)
            );
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
            """
        )
        conn.execute(
            """
            INSERT INTO bridge_deposits
                (tx_hash, query_id, query_type, status, state_ts, report_ts)
            VALUES ('0xkeep', '0xq', 'TRBBridge', 'good', 1, 1)
            """
        )
        conn.execute(
            "INSERT INTO eth_deposits (contract_address, deposit_id, first_seen_ts) VALUES (?, ?, ?)",
            (CONTRACT, 7, 1.0),
        )
        conn.execute("INSERT INTO meta (key, value) VALUES ('deposit_floor_abc', '1')")
        conn.commit()
        conn.close()

        led = BridgeLedger(path)
        tables = {r[0] for r in led.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "eth_deposits" not in tables
        assert "meta" not in tables
        assert led.get("0xkeep")["status"] == "good"
        led.close()
