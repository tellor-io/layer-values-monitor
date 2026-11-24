"""Persistent SQLite ledger for TRBBridge/TRBBridgeV2 deposit report verification.

This is the daemon's only durable state for bridge reports: every Layer-side bridge
report gets a row (Tier 1), and the reconciler task advances row statuses (Tier 2)
until the report is terminal. WAL mode gives crash recovery without write discipline;
the UNIQUE(tx_hash) constraint is the idempotency guard for catch-up replays.

Schema:
    bridge_deposits  one row per Layer report (keyed by report tx_hash)
    eth_deposits     ground truth from the bridge contract's deposits() state (counter sweep)
    meta             sweep floor/cursor keys per contract and misc keys
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Row statuses — exactly three, by design. Nothing is terminal except good/bad;
# unverified rows are retried by the reconciler forever until a real verdict.
STATUS_UNVERIFIED = "unverified"  # no verdict yet (RPC dead, or migrated from old statuses)
STATUS_GOOD = "good"  # trusted value matched the report (terminal)
STATUS_BAD = "bad"  # mismatch/zero-struct confirmed on the 60s confirm read (terminal)

TERMINAL_STATUSES = frozenset({STATUS_GOOD, STATUS_BAD})
RECHECK_STATUSES = (STATUS_UNVERIFIED,)

# Defaults (overridable via env in the callers)
DISPUTE_WINDOW_HOURS = 12
DEFAULT_RECONCILE_INTERVAL = 120  # seconds between reconciler cycles
DEFAULT_CONFIRM_SECONDS = 60  # delay before the confirm read that confirms a zero/mismatch
DEFAULT_REPORT_WINDOW_BLOCKS = 2000  # TRBBridgeV2 registry dataspec ReportBlockWindow (x/registry, v6.1.4 upgrade)
DEFAULT_LAYER_BLOCK_SECONDS = 12.0  # block-time estimate to turn the window into seconds
DEFAULT_MISSING_MAX_AGE_HOURS = 24.0  # older deposits retire silently — the MISSING alert is a timeliness check

DEFAULT_LEDGER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "bridge_ledger.db"
)


def default_ledger_path() -> str:
    """Ledger path from BRIDGE_LEDGER_PATH env, default ./data/bridge_ledger.db."""
    return os.getenv("BRIDGE_LEDGER_PATH", DEFAULT_LEDGER_PATH)


class BridgeLedger:
    """SQLite-backed journal of bridge deposit reports."""

    def __init__(self, path: str | None = None) -> None:
        """Open (and create if needed) the ledger database at path."""
        self.path = path or default_ledger_path()
        resolved = Path(self.path).expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(resolved)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS bridge_deposits (
                tx_hash          TEXT PRIMARY KEY,
                query_id         TEXT NOT NULL,
                query_type       TEXT NOT NULL,
                contract_address TEXT,
                deposit_id       INTEGER,
                reported_json    TEXT,
                status           TEXT NOT NULL,
                state_ts         REAL NOT NULL,
                report_ts        REAL NOT NULL,
                retries          INTEGER NOT NULL DEFAULT 0,
                last_error       TEXT,
                reporter         TEXT,
                power            TEXT,
                meta_id          TEXT,
                escalated        INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS eth_deposits (
                contract_address TEXT NOT NULL,
                deposit_id       INTEGER NOT NULL,
                eth_tx_hash      TEXT,
                log_block        INTEGER,
                block_ts         REAL,
                reported_json    TEXT,
                first_seen_ts    REAL NOT NULL,
                missing_report   INTEGER NOT NULL DEFAULT 0,
                missing_alerted  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (contract_address, deposit_id)
            );

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            """
        )
        # additive migrations for ledgers created before a column existed
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(eth_deposits)")}
        if "block_ts" not in cols:
            self.conn.execute("ALTER TABLE eth_deposits ADD COLUMN block_ts REAL")
        # one-time status migration to the three-status vocabulary. Old stranded statuses
        # map to `unverified` on purpose: previously-terminal rows resume retrying.
        self.conn.execute(
            """
            UPDATE bridge_deposits SET status = CASE status
              WHEN 'verified_ok' THEN 'good' WHEN 'resolved_lag' THEN 'good'
              WHEN 'disputed' THEN 'bad'
              WHEN 'unverifiable' THEN 'unverified' WHEN 'expired_unresolved' THEN 'unverified'
              ELSE status END
            WHERE status IN ('verified_ok','resolved_lag','disputed','unverifiable','expired_unresolved')
            """
        )
        self.conn.commit()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self.conn.close()

    # ------------------------------------------------------------------
    # bridge_deposits
    # ------------------------------------------------------------------

    def upsert_report(
        self,
        tx_hash: str,
        query_id: str,
        query_type: str,
        deposit_id: int | None,
        reported_value: dict | None,
        status: str,
        report_ts: float,
        contract_address: str | None = None,
        reporter: str | None = None,
        power: str | None = None,
        meta_id: str | None = None,
        last_error: str | None = None,
        state_ts: float | None = None,
    ) -> bool:
        """Insert a report row. Idempotent: an existing tx_hash (catch-up replay) is left untouched.

        Returns True when a new row was inserted, False when the row already existed.
        """
        cur = self.conn.execute(
            """
            INSERT INTO bridge_deposits
                (tx_hash, query_id, query_type, contract_address, deposit_id, reported_json,
                 status, state_ts, report_ts, retries, last_error, reporter, power, meta_id,
                 escalated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 0)
            ON CONFLICT(tx_hash) DO NOTHING
            """,
            (
                tx_hash,
                query_id,
                query_type,
                contract_address,
                deposit_id,
                json.dumps(reported_value) if reported_value is not None else None,
                status,
                time.time() if state_ts is None else state_ts,
                report_ts,
                last_error,
                reporter,
                power,
                meta_id,
            ),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def set_status(self, tx_hash: str, status: str, error: str | None = None, bump_retries: bool = False) -> None:
        """Advance a row's status; state_ts is refreshed for due_for_recheck timing."""
        self.conn.execute(
            """
            UPDATE bridge_deposits
            SET status = ?,
                state_ts = ?,
                last_error = COALESCE(?, last_error),
                retries = retries + ?
            WHERE tx_hash = ?
            """,
            (status, time.time(), error, 1 if bump_retries else 0, tx_hash),
        )
        self.conn.commit()

    def get(self, tx_hash: str) -> dict | None:
        """Fetch one bridge report row by tx_hash."""
        row = self.conn.execute("SELECT * FROM bridge_deposits WHERE tx_hash = ?", (tx_hash,)).fetchone()
        return dict(row) if row else None

    def due_for_recheck(self, now: float | None = None, interval: float = DEFAULT_RECONCILE_INTERVAL) -> list[dict]:
        """Unverified rows whose status hasn't been revisited within the reconcile interval.

        This throttle (state_ts <= now - interval) IS the retry-forever rule: unverified rows
        come back every cycle with no retry cap and no expiry — only good/bad end the loop.
        """
        now = time.time() if now is None else now
        rows = self.conn.execute(
            f"""
            SELECT * FROM bridge_deposits
            WHERE status IN ({", ".join("?" * len(RECHECK_STATUSES))})
              AND state_ts <= ?
            ORDER BY report_ts ASC
            """,
            (*RECHECK_STATUSES, now - interval),
        ).fetchall()
        return [dict(r) for r in rows]

    def near_deadline(
        self, now: float | None = None, hours: float = DISPUTE_WINDOW_HOURS, margin: float = 2.0
    ) -> list[dict]:
        """Non-terminal, not-yet-escalated rows older than (hours - margin) since the report."""
        now = time.time() if now is None else now
        rows = self.conn.execute(
            """
            SELECT * FROM bridge_deposits
            WHERE status NOT IN ({})
              AND escalated = 0
              AND report_ts <= ?
            """.format(",".join("?" * len(TERMINAL_STATUSES))),
            (*sorted(TERMINAL_STATUSES), now - (hours - margin) * 3600),
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_escalated(self, tx_hash: str) -> None:
        """Flag a row's deadline escalation alert as sent (alert-once)."""
        self.conn.execute("UPDATE bridge_deposits SET escalated = 1 WHERE tx_hash = ?", (tx_hash,))
        self.conn.commit()

    # ------------------------------------------------------------------
    # eth_deposits
    # ------------------------------------------------------------------

    def record_eth_deposit(
        self,
        contract_address: str,
        deposit_id: int,
        eth_tx_hash: str | None,
        log_block: int | None,
        reported_value: dict | None = None,
        block_ts: float | None = None,
    ) -> bool:
        """Record a Deposit event observed on eth. Returns True when newly recorded."""
        cur = self.conn.execute(
            """
            INSERT INTO eth_deposits
                (contract_address, deposit_id, eth_tx_hash, log_block, block_ts, reported_json,
                 first_seen_ts, missing_report, missing_alerted)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
            ON CONFLICT(contract_address, deposit_id) DO NOTHING
            """,
            (
                contract_address,
                deposit_id,
                eth_tx_hash,
                log_block,
                block_ts,
                json.dumps(reported_value) if reported_value is not None else None,
                time.time(),
            ),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def has_eth_deposit(self, contract_address: str, deposit_id: int) -> bool:
        """Check whether the deposit journal recorded this deposit."""
        row = self.conn.execute(
            "SELECT 1 FROM eth_deposits WHERE contract_address = ? AND deposit_id = ?",
            (contract_address, deposit_id),
        ).fetchone()
        return row is not None

    def pending_missing_reports(self, now: float | None = None, window_s: float = 24_000) -> list[dict]:
        """Eth deposits whose Layer reporting window has CLOSED with no report row yet (not alerted).

        Anchored on the deposit's block timestamp when known (the window is defined on-chain
        relative to the deposit), falling back to first-seen time for rows predating block_ts.
        """
        now = time.time() if now is None else now
        rows = self.conn.execute(
            """
            SELECT e.* FROM eth_deposits e
            WHERE e.missing_alerted = 0
              AND COALESCE(e.block_ts, e.first_seen_ts) + ? <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM bridge_deposits b
                  WHERE b.contract_address = e.contract_address AND b.deposit_id = e.deposit_id
              )
            """,
            (window_s, now),
        ).fetchall()
        return [dict(r) for r in rows]

    def resolve_missing_report(self, contract_address: str, deposit_id: int) -> None:
        """Quietly retire a pending missing-report deposit (e.g. late report found on oracle)."""
        self.conn.execute(
            "UPDATE eth_deposits SET missing_alerted = 1 WHERE contract_address = ? AND deposit_id = ?",
            (contract_address, deposit_id),
        )
        self.conn.commit()

    def mark_missing_report(self, contract_address: str, deposit_id: int) -> bool:
        """Flag an eth deposit as missing its Layer report. Returns True on the first flag (alert-once)."""
        cur = self.conn.execute(
            """
            UPDATE eth_deposits SET missing_report = 1, missing_alerted = 1
            WHERE contract_address = ? AND deposit_id = ? AND missing_alerted = 0
            """,
            (contract_address, deposit_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # meta
    # ------------------------------------------------------------------

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        """Read a meta-table value (sweep cursors etc.)."""
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        """Insert or update a meta-table value."""
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()


# Module-level singleton used by both the stream path and the reconciler task
_ledger: BridgeLedger | None = None


def get_bridge_ledger() -> BridgeLedger:
    """Process-wide ledger singleton at BRIDGE_LEDGER_PATH (default ./data/bridge_ledger.db)."""
    global _ledger
    if _ledger is None:
        _ledger = BridgeLedger()
        logger.info(f"Bridge ledger opened at {_ledger.path}")
    return _ledger


def reset_bridge_ledger_for_tests() -> None:
    """Drop the singleton (tests point BRIDGE_LEDGER_PATH at a tmp file)."""
    global _ledger
    if _ledger is not None:
        _ledger.close()
    _ledger = None
