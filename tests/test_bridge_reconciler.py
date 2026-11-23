"""Tests for the Tier 2 bridge reconciler (anchored recheck disputes, sweeps, deadlines)."""

import asyncio
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.bridge_ledger import (
    STATUS_DISPUTED,
    STATUS_EXPIRED_UNRESOLVED,
    STATUS_MISMATCH_PENDING,
    STATUS_UNVERIFIABLE,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED_OK,
    BridgeLedger,
)
from layer_values_monitor.bridge_reconciler import (
    check_deadlines,
    check_reports_without_logs,
    run_reconcile_cycle,
    sweep_deposit_logs,
)
from layer_values_monitor.custom_types import Metrics, Msg

import pytest

CONTRACT = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
REPORTED = {"eth_address": "0xaaa", "layer_address": "tellor1x", "amount": 100, "tip": 1}
TRUSTED_TUPLE = ("0xaaa", "tellor1x", 100, 1)
WRONG_TUPLE = ("0xbbb", "tellor1x", 55, 1)  # primary read disagrees with the report


def fake_metrics(warning=1.0):
    # LVM equality semantics: warning_threshold > 0 is the dispute gate; ==1.0 names the category
    return Metrics(
        metric="equality",
        alert_threshold=1.0,
        warning_threshold=warning,
        minor_threshold=0.0,
        major_threshold=0.0,
        pause_threshold=0.0,
    )


@pytest.fixture
def ledger(tmp_path):
    led = BridgeLedger(str(tmp_path / "ledger.db"))
    yield led
    led.close()


@pytest.fixture(autouse=True)
def bridge_env(monkeypatch):
    monkeypatch.setenv("TRBBRIDGE_CONTRACT_ADDRESS", CONTRACT)
    monkeypatch.delenv("TRBBRIDGEV2_CONTRACT_ADDRESS", raising=False)
    monkeypatch.delenv("TRBBRIDGE_CHAIN_ID", raising=False)
    # Keep built-in defaults (bridge_networks) out of scope: this file tests env-driven config,
    # and CHAIN_ID may leak in from a developer's .env via conftest's load_dotenv.
    monkeypatch.delenv("CHAIN_ID", raising=False)


def add_row(ledger, tx_hash="0xtx1", status=STATUS_MISMATCH_PENDING, retries=0, report_ts=None, deposit_id=7):
    ledger.upsert_report(
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
    if retries:
        ledger.conn.execute("UPDATE bridge_deposits SET retries = ? WHERE tx_hash = ?", (retries, tx_hash))
        ledger.conn.commit()


def make_config_watcher(warning=1.0):
    metrics = fake_metrics(warning=warning)
    return SimpleNamespace(get_metrics_for_query=lambda query_id, query_type: metrics)


def patched(fetch_return=None, fetch_side_effect=None):
    """Context pieces common to every recheck test (no secondary provider anymore)."""
    kwargs = {"return_value": fetch_return} if fetch_side_effect is None else {"side_effect": fetch_side_effect}
    return (
        patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()),
        patch("layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(**kwargs)),
        patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()),
    )


async def run_cycle(ledger, q, warning=1.0):
    patches = patched()
    with patches[0], patches[1], patches[2]:
        await run_reconcile_cycle(ledger, q, make_config_watcher(warning=warning), MagicMock(), interval=0)


class TestRecheckLogic:
    @pytest.mark.asyncio
    async def test_recheck_match_resolves_to_verified_ok(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED)
        q = asyncio.Queue()
        patches = patched((TRUSTED_TUPLE, "ok"))
        with patches[0], patches[1], patches[2]:
            await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_VERIFIED_OK
        assert q.empty()

    @pytest.mark.asyncio
    async def test_mismatch_cleared_on_recheck_alerts_resolved(self, ledger):
        """A standing mismatch that reads back clean on the anchored recheck: verified_ok + RESOLVED alert."""
        add_row(ledger)
        q = asyncio.Queue()
        patches = patched((TRUSTED_TUPLE, "ok"))
        with (
            patches[0],
            patches[1],
            patches[2],
            patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert,
        ):
            await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_VERIFIED_OK
        assert alert.call_count == 1
        assert "mismatch cleared" in alert.call_args.args[1]["Status"]
        assert q.empty()

    @pytest.mark.asyncio
    async def test_first_mismatch_on_unverified_marks_pending(self, ledger):
        """Mismatch on an unverified row: mark it; the NEXT cycle's anchored re-read disputes."""
        add_row(ledger, status=STATUS_UNVERIFIED)
        q = asyncio.Queue()
        patches = patched((WRONG_TUPLE, "ok"))
        with patches[0], patches[1], patches[2]:
            await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_MISMATCH_PENDING
        assert q.empty()

    @pytest.mark.asyncio
    async def test_anchored_recheck_mismatch_queues_dispute(self, ledger):
        """Single trusted primary read, finalized-anchored: a still-mismatching recheck disputes."""
        add_row(ledger)
        q = asyncio.Queue()
        patches = patched((WRONG_TUPLE, "ok"))
        with patches[0], patches[1], patches[2]:
            await run_reconcile_cycle(ledger, q, make_config_watcher(warning=1.0), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_DISPUTED
        msg = q.get_nowait()
        assert isinstance(msg, Msg)
        assert msg.category == "warning"
        assert msg.meta_id == "42"
        assert msg.query_id == "0xq"

    @pytest.mark.asyncio
    async def test_mismatch_stays_pending_when_disputes_disabled(self, ledger):
        """Equality dispute thresholds of 0.0 disable disputes — rollout (alert-only) mode."""
        add_row(ledger)
        q = asyncio.Queue()
        await run_cycle(ledger, q, warning=0.0)
        assert ledger.get("0xtx1")["status"] == STATUS_MISMATCH_PENDING
        assert q.empty()

    @pytest.mark.asyncio
    async def test_mismatch_pending_zero_struct_disputes(self, ledger):
        """A mismatch whose recheck reads zero struct (fake-deposit signature): dispute, not defer."""
        add_row(ledger)
        q = asyncio.Queue()
        patches = patched((None, "zero_struct"))
        with patches[0], patches[1], patches[2]:
            await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        row = ledger.get("0xtx1")
        assert row["status"] == STATUS_DISPUTED
        assert "zero struct" in row["last_error"]
        assert q.get_nowait().category == "warning"

    @pytest.mark.asyncio
    async def test_mismatch_pending_defers_on_rpc_error(self, ledger):
        """RPC loss on the recheck (rotation already tried inside fetch_deposit): defer, never age out."""
        add_row(ledger, report_ts=time.time() - 3 * 3600)
        q = asyncio.Queue()
        patches = patched((None, "rpc_error"))
        with patches[0], patches[1], patches[2]:
            await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        row = ledger.get("0xtx1")
        assert row["status"] == STATUS_MISMATCH_PENDING
        assert row["retries"] == 1  # keeps trying; never goes unverifiable while a mismatch stands
        assert q.empty()

    @pytest.mark.asyncio
    async def test_unverified_zero_struct_not_disputed(self, ledger):
        """A never-verified row reading zero struct is flagged unverifiable, not disputed."""
        add_row(ledger, status=STATUS_UNVERIFIED, retries=5)
        q = asyncio.Queue()
        patches = patched((None, "zero_struct"))
        with (
            patches[0],
            patches[1],
            patches[2],
            patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert"),
        ):
            await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_UNVERIFIABLE
        assert q.empty()

    @pytest.mark.asyncio
    async def test_unverifiable_after_max_retries(self, ledger):
        os.environ["BRIDGE_UNVERIFIABLE_RETRIES"] = "6"
        try:
            add_row(ledger, status=STATUS_UNVERIFIED, retries=5)
            q = asyncio.Queue()
            patches = patched((None, "rpc_error"))
            with (
                patches[0],
                patches[1],
                patches[2],
                patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert,
            ):
                await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
            assert ledger.get("0xtx1")["status"] == STATUS_UNVERIFIABLE
            alert.assert_called_once()
        finally:
            del os.environ["BRIDGE_UNVERIFIABLE_RETRIES"]


class TestDeadlines:
    @pytest.mark.asyncio
    async def test_escalation_alerts_once_near_deadline(self, ledger):
        add_row(ledger, report_ts=time.time() - 10.5 * 3600)
        logger = MagicMock()
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_deadlines(ledger, logger)
            await check_deadlines(ledger, logger)
        assert alert.call_count == 1
        assert "dispute window" in alert.call_args.args[1]["Detail"]
        assert ledger.get("0xtx1")["escalated"] == 1

    @pytest.mark.asyncio
    async def test_escalation_does_not_repeat_after_restart(self, tmp_path):
        """escalated=1 lives in the SQLite row, not memory: a reopened ledger must not re-escalate."""
        path = str(tmp_path / "restart.db")
        led = BridgeLedger(path)
        add_row(led, report_ts=time.time() - 10.5 * 3600)
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_deadlines(led, MagicMock())
        assert alert.call_count == 1
        led.close()

        led2 = BridgeLedger(path)
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert2:
            await check_deadlines(led2, MagicMock())
        assert alert2.call_count == 0
        led2.close()

    @pytest.mark.asyncio
    async def test_expired_after_full_window(self, ledger):
        add_row(ledger, report_ts=time.time() - 13 * 3600)
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert"):
            await check_deadlines(ledger, MagicMock())
        assert ledger.get("0xtx1")["status"] == STATUS_EXPIRED_UNRESOLVED


class TestLogSweep:
    def make_w3(self, latest=150, latest_ts=None):
        latest_ts = latest_ts or int(time.time())
        w3 = MagicMock()
        w3.eth.block_number = latest

        def get_block(arg):
            if arg == "latest":
                return {"timestamp": latest_ts}
            # block-number lookup for the first-run timestamp search: 1 block/second back from latest
            return {"timestamp": latest_ts - (latest - int(arg))}

        w3.eth.get_block.side_effect = get_block
        return w3

    @pytest.mark.asyncio
    async def test_sweep_follows_latest_block(self, ledger):
        """No finalized wait: the sweep target is simply w3.eth.block_number."""
        w3 = self.make_w3(latest=321)
        w3.eth.get_logs.return_value = []
        await sweep_deposit_logs(ledger, MagicMock(), 111555111, w3=w3)
        cursor = ledger.get_meta(f"sweep_cursor_{CONTRACT.lower()}")
        assert cursor == "321" or int(cursor) == 321

    @pytest.mark.asyncio
    async def test_sweep_records_deposits_and_advances_cursor(self, ledger):
        w3 = self.make_w3()
        log_entry = {"transactionHash": b"\xab" * 32, "blockNumber": 120}
        w3.eth.get_logs.return_value = [log_entry]
        decoded = {"deposit_id": 7, "sender": "0xaaa", "recipient": "tellor1x", "amount": 100, "tip": 1}
        with patch("layer_values_monitor.bridge_reconciler.decode_deposit_log", side_effect=[decoded]):
            await sweep_deposit_logs(ledger, MagicMock(), 111555111, w3=w3)

        assert ledger.has_eth_deposit(CONTRACT, 7) is True
        cursor = ledger.get_meta(f"sweep_cursor_{CONTRACT.lower()}")
        assert cursor is not None and int(cursor) >= 120

        # Second sweep with no new range must not re-record or re-alert
        w3.eth.get_logs.return_value = []
        with patch("layer_values_monitor.bridge_reconciler.decode_deposit_log") as dec:
            await sweep_deposit_logs(ledger, MagicMock(), 111555111, w3=w3)
        dec.assert_not_called() if int(cursor) >= 150 else None  # caught up: no decode at all
        assert ledger.record_eth_deposit(CONTRACT, 7, "0x", 121) is False


class TestReportsWithoutLogs:
    @pytest.mark.asyncio
    async def test_report_without_log_flagged_unverifiable(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED, deposit_id=77)
        ledger.set_meta(f"sweep_start_ts_{CONTRACT.lower()}", "0")  # sweep covers everything
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_reports_without_logs(ledger, MagicMock(), now=time.time() + 7200)
        assert ledger.get("0xtx1")["status"] == STATUS_UNVERIFIABLE
        assert "never emitted" in alert.call_args.args[1]["Detail"]

    @pytest.mark.asyncio
    async def test_fresh_report_without_log_waits_out_grace(self, ledger):
        """A report minutes after its deposit outruns the sweep (which trails the tip by a
        cycle): a missing Deposit log must NOT declare it unverifiable yet."""
        add_row(ledger, status=STATUS_MISMATCH_PENDING, deposit_id=170)
        ledger.set_meta(f"sweep_start_ts_{CONTRACT.lower()}", "0")
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_reports_without_logs(ledger, MagicMock())  # report_ts == now
        assert ledger.get("0xtx1")["status"] == STATUS_MISMATCH_PENDING
        alert.assert_not_called()

    @pytest.mark.asyncio
    async def test_report_with_log_left_alone(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED, deposit_id=7)
        ledger.record_eth_deposit(CONTRACT, 7, "0xeth", 100, REPORTED)
        ledger.set_meta(f"sweep_start_ts_{CONTRACT.lower()}", "0")
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert"):
            await check_reports_without_logs(ledger, MagicMock())
        assert ledger.get("0xtx1")["status"] == STATUS_UNVERIFIED
