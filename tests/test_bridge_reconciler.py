"""Tests for the Tier 2 bridge reconciler (double-confirmation, sweeps, deadlines)."""

import asyncio
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.bridge_ledger import (
    STATUS_DISPUTED,
    STATUS_EXPIRED_UNRESOLVED,
    STATUS_MISMATCH_PENDING,
    STATUS_RESOLVED_LAG,
    STATUS_UNVERIFIABLE,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED_OK,
    BridgeLedger,
)
from layer_values_monitor.bridge_reconciler import (
    check_deadlines,
    check_orphans_and_missing,
    run_reconcile_cycle,
    sweep_deposit_logs,
)
from layer_values_monitor.custom_types import Metrics, Msg

import pytest

CONTRACT = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
REPORTED = {"eth_address": "0xaaa", "layer_address": "tellor1x", "amount": 100, "tip": 1}
TRUSTED_TUPLE = ("0xaaa", "tellor1x", 100, 1)
WRONG_TUPLE = ("0xbbb", "tellor1x", 55, 1)  # both providers agree, report disagrees


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
    monkeypatch.delenv("BRIDGE_SECONDARY_RPC_URL", raising=False)


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


class TestRecheckLogic:
    @pytest.mark.asyncio
    async def test_recheck_match_resolves_to_verified_ok(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED)
        q = asyncio.Queue()
        with patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()):
            with patch(
                "layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(return_value=(TRUSTED_TUPLE, "ok"))
            ):
                with patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()):
                    await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_VERIFIED_OK

    @pytest.mark.asyncio
    async def test_secondary_matching_report_clears_as_lag(self, ledger):
        """Primary says mismatch, secondary matches the report → resolved_lag, no dispute (log-only)."""
        add_row(ledger)
        q = asyncio.Queue()
        calls = [
            (WRONG_TUPLE, "ok"),  # primary re-read
            (TRUSTED_TUPLE, "ok"),  # secondary read matches report
        ]
        with patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()):
            with patch("layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(side_effect=calls)):
                with patch("layer_values_monitor.bridge_reconciler.get_secondary_connection", return_value=MagicMock()):
                    with patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()):
                        await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_RESOLVED_LAG
        assert q.empty()

    @pytest.mark.asyncio
    async def test_confirmed_mismatch_queues_dispute(self, ledger):
        """Both providers independently agree on the same wrong value → dispute queued."""
        add_row(ledger)
        q = asyncio.Queue()
        calls = [(WRONG_TUPLE, "ok"), (WRONG_TUPLE, "ok")]
        with patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()):
            with patch("layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(side_effect=calls)):
                with patch("layer_values_monitor.bridge_reconciler.get_secondary_connection", return_value=MagicMock()):
                    with patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()):
                        await run_reconcile_cycle(ledger, q, make_config_watcher(warning=1.0), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_DISPUTED
        msg = q.get_nowait()
        assert isinstance(msg, Msg)
        assert msg.category == "warning"
        assert msg.meta_id == "42"
        assert msg.query_id == "0xq"

    @pytest.mark.asyncio
    async def test_confirmed_mismatch_stays_pending_when_disputes_disabled(self, ledger):
        """Equality dispute thresholds of 0.0 disable disputes — rollout (alert-only) mode."""
        add_row(ledger)
        q = asyncio.Queue()
        calls = [(WRONG_TUPLE, "ok"), (WRONG_TUPLE, "ok")]
        with patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()):
            with patch("layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(side_effect=calls)):
                with patch("layer_values_monitor.bridge_reconciler.get_secondary_connection", return_value=MagicMock()):
                    with patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()):
                        await run_reconcile_cycle(ledger, q, make_config_watcher(warning=0.0), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_MISMATCH_PENDING
        assert q.empty()

    @pytest.mark.asyncio
    async def test_missing_secondary_never_disputes(self, ledger):
        add_row(ledger)
        q = asyncio.Queue()
        with patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()):
            with patch(
                "layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(return_value=(WRONG_TUPLE, "ok"))
            ):
                with patch("layer_values_monitor.bridge_reconciler.get_secondary_connection", return_value=None):
                    with patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()):
                        await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        row = ledger.get("0xtx1")
        assert row["status"] == STATUS_MISMATCH_PENDING
        assert row["retries"] == 1  # deferred, retried next cycle
        assert q.empty()

    @pytest.mark.asyncio
    async def test_zero_struct_read_never_confirms_mismatch(self, ledger):
        """A zero-struct on recheck counts as a failed read, not a confirmed mismatch."""
        add_row(ledger)
        q = asyncio.Queue()
        with patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()):
            with patch(
                "layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(return_value=(None, "zero_struct"))
            ):
                with patch(
                    "layer_values_monitor.bridge_reconciler.get_secondary_connection", return_value=MagicMock()
                ) as sec:
                    with patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()):
                        await run_reconcile_cycle(ledger, q, make_config_watcher(), MagicMock(), interval=0)
        assert ledger.get("0xtx1")["status"] == STATUS_MISMATCH_PENDING
        sec.assert_not_called()
        assert q.empty()

    @pytest.mark.asyncio
    async def test_unverifiable_after_max_retries(self, ledger):
        os.environ["BRIDGE_UNVERIFIABLE_RETRIES"] = "6"
        try:
            add_row(ledger, status=STATUS_UNVERIFIED, retries=5)
            q = asyncio.Queue()
            with patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()):
                with patch(
                    "layer_values_monitor.bridge_reconciler.fetch_deposit", new=AsyncMock(return_value=(None, "rpc_error"))
                ):
                    with patch("layer_values_monitor.bridge_reconciler.sweep_deposit_logs", new=AsyncMock()):
                        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
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
    async def test_expired_after_full_window(self, ledger):
        add_row(ledger, report_ts=time.time() - 13 * 3600)
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert"):
            await check_deadlines(ledger, MagicMock())
        assert ledger.get("0xtx1")["status"] == STATUS_EXPIRED_UNRESOLVED


class TestLogSweep:
    def make_w3(self, monkeypatch, finalized=150, latest_ts=None):
        latest_ts = latest_ts or int(time.time())
        w3 = MagicMock()
        w3.eth.block_number = finalized

        def get_block(arg):
            if arg == "finalized":
                return {"number": finalized}
            if arg == "latest":
                return {"timestamp": latest_ts}
            # block-number lookup for the first-run timestamp search: 1 block/second back from latest
            return {"timestamp": latest_ts - (finalized - int(arg))}

        w3.eth.get_block.side_effect = get_block
        return w3

    @pytest.mark.asyncio
    async def test_sweep_records_deposits_and_advances_cursor(self, ledger):
        w3 = self.make_w3(ledger)
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

    @pytest.mark.asyncio
    async def test_missing_report_alerts_once(self, ledger):
        ledger.record_eth_deposit(CONTRACT, 8, "0xeth", 100, REPORTED)  # no Layer report
        now = time.time() + 7200  # deposit is now 2h old
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_orphans_and_missing(ledger, MagicMock(), now=now)
            await check_orphans_and_missing(ledger, MagicMock(), now=now)
        assert alert.call_count == 1
        assert "no Layer report" in alert.call_args.args[1]["Detail"]

    @pytest.mark.asyncio
    async def test_report_without_log_flagged_unverifiable(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED, deposit_id=77)
        ledger.set_meta(f"sweep_start_ts_{CONTRACT.lower()}", "0")  # sweep covers everything
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_orphans_and_missing(ledger, MagicMock(), now=time.time() + 7200)
        assert ledger.get("0xtx1")["status"] == STATUS_UNVERIFIABLE
        assert "never emitted" in alert.call_args.args[1]["Detail"]

    @pytest.mark.asyncio
    async def test_fresh_report_without_log_waits_out_grace(self, ledger):
        """A report minutes after its deposit outruns the finalized-anchored sweep:
        a missing Deposit log must NOT declare it unverifiable yet."""
        add_row(ledger, status=STATUS_MISMATCH_PENDING, deposit_id=170)
        ledger.set_meta(f"sweep_start_ts_{CONTRACT.lower()}", "0")
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_orphans_and_missing(ledger, MagicMock())  # report_ts == now
        assert ledger.get("0xtx1")["status"] == STATUS_MISMATCH_PENDING
        alert.assert_not_called()

    @pytest.mark.asyncio
    async def test_report_with_log_left_alone(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED, deposit_id=7)
        ledger.record_eth_deposit(CONTRACT, 7, "0xeth", 100, REPORTED)
        ledger.set_meta(f"sweep_start_ts_{CONTRACT.lower()}", "0")
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert"):
            await check_orphans_and_missing(ledger, MagicMock())
        assert ledger.get("0xtx1")["status"] == STATUS_UNVERIFIED
