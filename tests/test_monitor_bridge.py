"""Tests for Tier 1 wiring: bridge reports reach inline verdicts and dispute confirmed-bad directly."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.bridge_ledger import (
    STATUS_BAD,
    STATUS_GOOD,
    STATUS_UNVERIFIED,
    BridgeLedger,
)
from layer_values_monitor.custom_types import Metrics, Msg, NewReport

import pytest

CONTRACT = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
TRUSTED = {"eth_address": "0xaaa", "layer_address": "tellor1x", "amount": 100, "tip": 1}
WRONG = {"eth_address": "0xaaa", "layer_address": "tellor1x", "amount": 999, "tip": 1}


def make_report(tx_hash="0xtx1"):
    return NewReport(
        query_type="TRBBridge",
        query_data="0x" + "0" * 63 + "7",  # deposit id 7
        query_id="0xq",
        value="0xdeadbeef",
        aggregate_method="weighted-median",
        cyclelist="layer-1",
        power="1000",
        reporter="tellor1rep",
        timestamp="1234567890000",
        meta_id="42",
        tx_hash=tx_hash,
    )


def equality_metrics(warning=1.0, minor=0.0, major=0.0):
    return Metrics(
        metric="equality",
        alert_threshold=1.0,
        warning_threshold=warning,
        minor_threshold=minor,
        major_threshold=major,
        pause_threshold=0.0,
    )


@pytest.fixture
def bridge_env(monkeypatch, tmp_path):
    monkeypatch.setenv("TRBBRIDGE_CONTRACT_ADDRESS", CONTRACT)
    monkeypatch.setenv("TRBBRIDGE_CHAIN_ID", "11155111")
    return BridgeLedger(str(tmp_path / "ledger.db"))


async def run_inspection(ledger, verdict_result, reported=None):
    """Drive inspect_trbbridge_reports with the shared verdict helper mocked."""
    from layer_values_monitor.monitor import inspect_trbbridge_reports

    disputes_q = asyncio.Queue()
    logger = MagicMock()
    with patch("layer_values_monitor.monitor.get_bridge_ledger", return_value=ledger):
        with patch("layer_values_monitor.monitor.make_provider_builder", return_value=MagicMock()):
            with patch(
                "layer_values_monitor.monitor.decode_report_value",
                return_value=(reported or ("0xaaa", "tellor1x", 100, 1)),
            ):
                with patch(
                    "layer_values_monitor.monitor.get_bridge_verdict",
                    new=AsyncMock(return_value=verdict_result),
                ):
                    with patch("layer_values_monitor.monitor.generic_alert"):
                        with patch("layer_values_monitor.monitor.add_to_table"):
                            await inspect_trbbridge_reports(
                                [make_report()], disputes_q, "0xq", equality_metrics(), logger
                            )
    return disputes_q


@pytest.mark.asyncio
async def test_verdict_ok_records_good(bridge_env):
    """Match (or mismatch unconfirmed by the confirm read) -> good, nothing queued."""
    q = await run_inspection(bridge_env, ("ok", TRUSTED))
    row = bridge_env.get("0xtx1")
    assert row["status"] == STATUS_GOOD
    assert json.loads(row["reported_json"])["amount"] == 100
    assert q.empty()


@pytest.mark.asyncio
async def test_verdict_bad_records_bad_and_queues_dispute(bridge_env):
    """Confirmed mismatch: status bad AND the dispute Msg queued straight from inspect()."""
    q = await run_inspection(bridge_env, ("bad", TRUSTED), reported=("0xaaa", "tellor1x", 999, 1))
    row = bridge_env.get("0xtx1")
    assert row["status"] == STATUS_BAD
    assert row["last_error"] == "tier1_confirmed_bad"
    msg = q.get_nowait()
    assert isinstance(msg, Msg)
    assert msg.category == "warning"
    assert msg.query_id == "0xq"


@pytest.mark.asyncio
async def test_verdict_bad_alert_only_mode_records_bad_without_dispute(bridge_env):
    """Threshold 0.0 (alert-only): bad is recorded, inspect() queues nothing."""
    from layer_values_monitor.monitor import inspect_trbbridge_reports

    disputes_q = asyncio.Queue()
    with patch("layer_values_monitor.monitor.get_bridge_ledger", return_value=bridge_env):
        with patch("layer_values_monitor.monitor.make_provider_builder", return_value=MagicMock()):
            with patch(
                "layer_values_monitor.monitor.decode_report_value",
                return_value=("0xaaa", "tellor1x", 999, 1),
            ):
                with patch(
                    "layer_values_monitor.monitor.get_bridge_verdict",
                    new=AsyncMock(return_value=("bad", TRUSTED)),
                ):
                    with patch("layer_values_monitor.monitor.generic_alert"):
                        with patch("layer_values_monitor.monitor.add_to_table"):
                            await inspect_trbbridge_reports(
                                [make_report()], disputes_q, "0xq", equality_metrics(warning=0.0), MagicMock()
                            )
    assert bridge_env.get("0xtx1")["status"] == STATUS_BAD
    assert disputes_q.empty()


@pytest.mark.asyncio
async def test_verdict_unavailable_records_unverified_and_alerts(bridge_env):
    """All-RPC loss = persisted unverified row + the NO FUNCTIONAL RPC alert, never a silent skip."""
    with patch("layer_values_monitor.monitor.bridge_ledger_alert") as alert:
        q = await run_inspection(bridge_env, ("unavailable", None))
    row = bridge_env.get("0xtx1")
    assert row["status"] == STATUS_UNVERIFIED
    assert row["last_error"] == "rpc_error"
    alert.assert_called_once()
    assert "NO FUNCTIONAL RPC AVAILABLE" in alert.call_args.args[0]
    assert q.empty()


@pytest.mark.asyncio
async def test_unavailable_alert_fires_once_per_tx_hash(bridge_env):
    """Catch-up replay of the same report must not re-alert (idempotency guard)."""
    with patch("layer_values_monitor.monitor.bridge_ledger_alert") as alert:
        await run_inspection(bridge_env, ("unavailable", None))
        await run_inspection(bridge_env, ("unavailable", None))
    assert alert.call_count == 1


@pytest.mark.asyncio
async def test_inspect_defer_dispute_skips_queue_put():
    """Direct unit check of inspect(): defer_dispute suppresses only the disputes_q.put."""
    from layer_values_monitor.monitor import inspect

    disputes_q = asyncio.Queue()
    with (
        patch("layer_values_monitor.monitor.add_to_table"),
        patch("layer_values_monitor.monitor.generic_alert"),
    ):
        await inspect(
            make_report(),
            {"a": 1},
            {"a": 2},
            disputes_q,
            equality_metrics(warning=1.0, minor=0.0),
            MagicMock(),
            query=None,
            defer_dispute=True,
        )
    assert disputes_q.empty()

    with (
        patch("layer_values_monitor.monitor.add_to_table"),
        patch("layer_values_monitor.monitor.generic_alert"),
    ):
        await inspect(
            make_report(),
            {"a": 1},
            {"a": 2},
            disputes_q,
            equality_metrics(warning=1.0, minor=0.0),
            MagicMock(),
            query=None,
            defer_dispute=False,
        )
    msg = disputes_q.get_nowait()
    assert isinstance(msg, Msg)
    assert msg.category == "warning"


@pytest.mark.asyncio
async def test_lowercase_env_address_recorded_checksummed(bridge_env, monkeypatch):
    """Ledger rows store the checksummed address: the reconciler's SQL joins compare exact
    strings against the checksummed env values the deposit sweep writes into eth_deposits."""
    monkeypatch.setenv("TRBBRIDGE_CONTRACT_ADDRESS", CONTRACT.lower())
    await run_inspection(bridge_env, ("ok", TRUSTED))
    assert bridge_env.get("0xtx1")["contract_address"] == CONTRACT
