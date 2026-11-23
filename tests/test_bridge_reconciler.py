"""Tests for the Tier 2 bridge reconciler (retry-forever, verdict disputes, counter sweep, deadlines)."""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.bridge_ledger import (
    STATUS_BAD,
    STATUS_GOOD,
    STATUS_UNVERIFIED,
    BridgeLedger,
)
from layer_values_monitor.bridge_reconciler import (
    bridge_reconcile_loop,
    check_deadlines,
    check_missing_reports,
    run_reconcile_cycle,
    sweep_deposits,
)
from layer_values_monitor.custom_types import Metrics, Msg
from layer_values_monitor.trb_bridge import ZERO_ADDRESS

import pytest

CONTRACT = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
REPORTED = {"eth_address": "0xaaa", "layer_address": "tellor1x", "amount": 100, "tip": 1}
TRUSTED = {"eth_address": "0xaaa", "layer_address": "tellor1x", "amount": 100, "tip": 1}
WRONG = {"eth_address": "0xbbb", "layer_address": "tellor1x", "amount": 55, "tip": 1}
ZERO_STRUCT = (ZERO_ADDRESS, "", 0, 0, 0)


def deposit_struct(amount=100, block=100):
    return ("0x7660794ef8f978ea0922dc29b3b534d93e1fc94a", "tellor1x", amount, 1, block)


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
    monkeypatch.delenv("CHAIN_ID", raising=False)
    monkeypatch.delenv("LAYER_REST_URL", raising=False)
    monkeypatch.setenv("BRIDGE_REPORT_WINDOW_BLOCKS", "1000")
    monkeypatch.setenv("BRIDGE_LAYER_BLOCK_SECONDS", "3")


def add_row(ledger, tx_hash="0xtx1", status=STATUS_UNVERIFIED, retries=0, report_ts=None, deposit_id=7):
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


def patched(verdict_result):
    """Run-a-cycle patches: scripted verdict, no sweep, no orphan check."""
    return (
        patch("layer_values_monitor.bridge_reconciler.make_provider_builder", return_value=MagicMock()),
        patch("layer_values_monitor.bridge_reconciler.get_bridge_verdict", new=AsyncMock(return_value=verdict_result)),
        patch("layer_values_monitor.bridge_reconciler.sweep_deposits", new=AsyncMock()),
        patch("layer_values_monitor.bridge_reconciler.check_missing_reports", new=AsyncMock()),
    )


async def run_cycle_with_verdict(ledger, q, verdict_result, warning=1.0):
    """Run one cycle with a scripted verdict. Returns the bridge_ledger_alert mock used."""
    ps = patched(verdict_result)
    with ps[0], ps[1], ps[2], ps[3], patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
        await run_reconcile_cycle(
            ledger, q, make_config_watcher(warning=warning), MagicMock(), interval=0, chain_id=11155111
        )
    return alert


class TestRecheckLogic:
    @pytest.mark.asyncio
    async def test_verdict_ok_marks_good_and_alerts_resolved(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED, retries=3)
        q = asyncio.Queue()
        alert = await run_cycle_with_verdict(ledger, q, ("ok", TRUSTED))
        assert ledger.get("0xtx1")["status"] == STATUS_GOOD
        alert.assert_called_once()
        assert "RESOLVED" in alert.call_args.args[0]
        assert q.empty()

    @pytest.mark.asyncio
    async def test_verdict_bad_inside_window_disputes(self, ledger):
        add_row(ledger, report_ts=time.time() - 3600)  # well inside the 12h window
        q = asyncio.Queue()
        alert = await run_cycle_with_verdict(ledger, q, ("bad", WRONG))
        assert ledger.get("0xtx1")["status"] == STATUS_BAD
        msg = q.get_nowait()
        assert isinstance(msg, Msg)
        assert msg.category == "warning"
        assert msg.meta_id == "42"
        assert msg.query_id == "0xq"
        assert "DISPUTED" in alert.call_args.args[0]

    @pytest.mark.asyncio
    async def test_verdict_bad_past_window_alerts_late_without_dispute(self, ledger):
        add_row(ledger, report_ts=time.time() - 13 * 3600)  # dispute window already closed
        q = asyncio.Queue()
        alert = await run_cycle_with_verdict(ledger, q, ("bad", WRONG))
        assert ledger.get("0xtx1")["status"] == STATUS_BAD
        assert q.empty()
        assert "LATE VERDICT" in alert.call_args.args[0]

    @pytest.mark.asyncio
    async def test_unavailable_stays_unverified_and_retries_forever(self, ledger):
        """No retry cap: a row on its 100th failed read is still retried, status unchanged."""
        add_row(ledger, status=STATUS_UNVERIFIED, retries=99)
        q = asyncio.Queue()
        alert = await run_cycle_with_verdict(ledger, q, ("unavailable", None))
        row = ledger.get("0xtx1")
        assert row["status"] == STATUS_UNVERIFIED
        assert row["retries"] == 100
        assert q.empty()
        alert.assert_not_called()  # the row was already alerted when recorded
        # still comes back next cycle
        due = ledger.due_for_recheck(now=time.time() + 3600, interval=600)
        assert [r["tx_hash"] for r in due] == ["0xtx1"]

    @pytest.mark.asyncio
    async def test_bad_with_disputes_disabled_still_marks_bad(self, ledger):
        """Threshold 0.0 (alert-only rollout): the verdict is recorded, nothing is queued."""
        add_row(ledger, report_ts=time.time() - 3600)
        q = asyncio.Queue()
        await run_cycle_with_verdict(ledger, q, ("bad", WRONG), warning=0.0)
        assert ledger.get("0xtx1")["status"] == STATUS_BAD
        assert q.empty()

    @pytest.mark.asyncio
    async def test_good_and_bad_rows_are_not_rechecked(self, ledger):
        add_row(ledger, tx_hash="0xg", status=STATUS_GOOD)
        add_row(ledger, tx_hash="0xb", status=STATUS_BAD)
        q = asyncio.Queue()
        await run_cycle_with_verdict(ledger, q, ("ok", TRUSTED))
        assert ledger.get("0xg")["status"] == STATUS_GOOD
        assert ledger.get("0xb")["status"] == STATUS_BAD


class TestDeadlines:
    @pytest.mark.asyncio
    async def test_escalation_alerts_once_with_undisputable_wording(self, ledger):
        add_row(ledger, status=STATUS_UNVERIFIED, report_ts=time.time() - 10.5 * 3600)
        logger = MagicMock()
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_deadlines(ledger, logger)
            await check_deadlines(ledger, logger)
        assert alert.call_count == 1
        assert "UNDISPUTABLE" in alert.call_args.args[0]
        assert "left" in alert.call_args.args[1]["Detail"]
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
    async def test_terminal_rows_never_escalate(self, ledger):
        old = time.time() - 10.5 * 3600
        add_row(ledger, tx_hash="0xg", status=STATUS_GOOD, report_ts=old)
        add_row(ledger, tx_hash="0xb", status=STATUS_BAD, report_ts=old)
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_deadlines(ledger, MagicMock())
        alert.assert_not_called()


class TestCounterSweep:
    def make_w3(self, counter, structs, probe_error_at=None):
        """Fake Web3: depositId() -> counter; deposits(i) -> struct or zero struct."""
        probed = []
        bridge = MagicMock()
        bridge.functions.depositId.return_value.call.return_value = counter

        def deposits(dep_id):
            probed.append(dep_id)
            if probe_error_at is not None and dep_id == probe_error_at:
                det = SimpleNamespace(call=MagicMock(side_effect=Exception("rpc down")))
            else:
                det = SimpleNamespace(call=lambda: structs.get(dep_id, ZERO_STRUCT))
            return det

        bridge.functions.deposits.side_effect = deposits
        w3 = MagicMock()
        w3.eth.contract.return_value = bridge
        w3.eth.get_block.return_value = {"timestamp": 1_700_000_000}
        return w3, probed

    @pytest.mark.asyncio
    async def test_first_run_backfill_stops_at_init_floor(self, ledger):
        """Mainnet V2 was seeded from V1: ids below the init read zero — that's the floor."""
        w3, probed = self.make_w3(counter=3, structs={1: deposit_struct(10), 2: deposit_struct(20)})
        await sweep_deposits(ledger, MagicMock(), 11155111, w3=w3)

        assert probed == [2, 1, 0]  # downward probe stops at the first zero struct
        assert ledger.has_eth_deposit(CONTRACT, 1) is True
        assert ledger.has_eth_deposit(CONTRACT, 2) is True
        assert ledger.has_eth_deposit(CONTRACT, 0) is False  # below the seeded floor
        assert ledger.get_meta(f"deposit_floor_{CONTRACT.lower()}") == "1"
        assert ledger.get_meta(f"deposit_next_{CONTRACT.lower()}") == "3"

        row = ledger.conn.execute("SELECT * FROM eth_deposits WHERE deposit_id = 1").fetchone()
        assert row["eth_tx_hash"] == ""  # unknown from a state read
        assert row["block_ts"] == 1_700_000_000  # anchored on the deposit block
        assert row["log_block"] == 100

    @pytest.mark.asyncio
    async def test_first_run_backfill_aborts_on_rpc_error(self, ledger):
        """A transient RPC error must not truncate history or record a floor."""
        w3, _ = self.make_w3(counter=2, structs={1: deposit_struct()}, probe_error_at=1)
        await sweep_deposits(ledger, MagicMock(), 11155111, w3=w3)
        assert ledger.get_meta(f"deposit_floor_{CONTRACT.lower()}") is None
        assert ledger.has_eth_deposit(CONTRACT, 1) is False

    @pytest.mark.asyncio
    async def test_counter_advance_records_only_new_ids(self, ledger):
        ledger.set_meta(f"deposit_floor_{CONTRACT.lower()}", "0")
        ledger.set_meta(f"deposit_next_{CONTRACT.lower()}", "2")
        w3, probed = self.make_w3(counter=4, structs={0: deposit_struct(), 1: deposit_struct(),
                                                       2: deposit_struct(30), 3: deposit_struct(40)})
        await sweep_deposits(ledger, MagicMock(), 11155111, w3=w3)
        assert probed == [2, 3]
        assert ledger.has_eth_deposit(CONTRACT, 2) is True
        assert ledger.has_eth_deposit(CONTRACT, 3) is True
        assert ledger.get_meta(f"deposit_next_{CONTRACT.lower()}") == "4"

        # no counter movement: probe nothing, change nothing
        probed.clear()
        await sweep_deposits(ledger, MagicMock(), 11155111, w3=w3)
        assert probed == []

    @pytest.mark.asyncio
    async def test_counter_decrease_is_silent_noop(self, ledger):
        """Reorg rewinds depositId(): cursor stays put, no alerts, no re-probing."""
        ledger.set_meta(f"deposit_floor_{CONTRACT.lower()}", "0")
        ledger.set_meta(f"deposit_next_{CONTRACT.lower()}", "5")
        w3, probed = self.make_w3(counter=3, structs={})
        await sweep_deposits(ledger, MagicMock(), 11155111, w3=w3)
        assert probed == []
        assert ledger.get_meta(f"deposit_next_{CONTRACT.lower()}") == "5"


class TestMissingReports:
    @pytest.mark.asyncio
    async def test_window_not_closed_stays_silent(self, ledger):
        ledger.record_eth_deposit(CONTRACT, 1, "", 100, REPORTED, block_ts=time.time() - 100)
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_missing_reports(ledger, MagicMock())
        alert.assert_not_called()

    @pytest.mark.asyncio
    async def test_window_closed_oracle_has_report_resolves_silently(self, ledger, monkeypatch):
        monkeypatch.setenv("LAYER_REST_URL", "http://rest.test")
        ledger.record_eth_deposit(CONTRACT, 1, "", 100, REPORTED, block_ts=time.time() - 4000)
        with (
            patch("layer_values_monitor.bridge_reconciler._layer_has_report", new=AsyncMock(return_value=True)),
            patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert,
        ):
            await check_missing_reports(ledger, MagicMock())
        alert.assert_not_called()
        assert ledger.pending_missing_reports(window_s=1) == []

    @pytest.mark.asyncio
    async def test_window_closed_rest_unreachable_alerts_with_caveat(self, ledger, monkeypatch):
        monkeypatch.setenv("LAYER_REST_URL", "http://rest.test")
        ledger.record_eth_deposit(CONTRACT, 1, "", 100, REPORTED, block_ts=time.time() - 4000)
        with (
            patch("layer_values_monitor.bridge_reconciler._layer_has_report",
                  new=AsyncMock(side_effect=Exception("connection refused"))),
            patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert,
        ):
            await check_missing_reports(ledger, MagicMock())
        alert.assert_called_once()
        assert "MISSING" in alert.call_args.args[0]
        assert "oracle REST unconfirmed" in alert.call_args.args[1]["Detail"]

    @pytest.mark.asyncio
    async def test_alert_fires_once(self, ledger):
        ledger.record_eth_deposit(CONTRACT, 1, "", 100, REPORTED, block_ts=time.time() - 4000)
        with patch("layer_values_monitor.bridge_reconciler.bridge_ledger_alert") as alert:
            await check_missing_reports(ledger, MagicMock())
            await check_missing_reports(ledger, MagicMock())
        alert.assert_called_once()


class TestLoopStartup:
    @pytest.mark.asyncio
    async def test_first_cycle_runs_before_first_sleep(self, ledger):
        """Check-on-start rule: the loop cycles immediately, then sleeps between cycles."""
        calls = []

        async def fake_cycle(*args, **kwargs):
            calls.append("cycle")

        async def fake_sleep(seconds):
            calls.append("sleep")
            raise asyncio.CancelledError

        with (
            patch("layer_values_monitor.bridge_reconciler.run_reconcile_cycle", new=fake_cycle),
            patch("layer_values_monitor.bridge_reconciler.asyncio.sleep", new=fake_sleep),
        ):
            with pytest.raises(asyncio.CancelledError):
                await bridge_reconcile_loop(asyncio.Queue(), None, MagicMock(), ledger=ledger, interval=60)
        assert calls == ["cycle", "sleep"]
