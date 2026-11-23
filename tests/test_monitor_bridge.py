"""Tests for Tier 1 wiring: bridge reports record ledger verdicts and never dispute directly."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.bridge_ledger import (
    STATUS_MISMATCH_PENDING,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED_OK,
    BridgeLedger,
)
from layer_values_monitor.custom_types import Metrics, Msg, NewReport

import pytest

CONTRACT = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
TRUSTED = ("0xaaa", "tellor1x", 100, 1)


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


async def run_inspection(ledger, fetch_return, reported=("0xaaa", "tellor1x", 100, 1)):
    """Drive inspect_trbbridge_reports with the eth read mocked."""
    from layer_values_monitor.monitor import inspect_trbbridge_reports

    disputes_q = asyncio.Queue()
    logger = MagicMock()
    with patch("layer_values_monitor.monitor.get_bridge_ledger", return_value=ledger):
        with patch("layer_values_monitor.monitor.make_provider_builder", return_value=MagicMock()):
            with patch("layer_values_monitor.monitor.decode_report_value", return_value=reported):
                with patch("layer_values_monitor.monitor.fetch_deposit", new=AsyncMock(return_value=fetch_return)):
                    with patch("layer_values_monitor.monitor.generic_alert"):
                        with patch("layer_values_monitor.monitor.add_to_table"):
                            await inspect_trbbridge_reports(
                                [make_report()], disputes_q, "0xq", equality_metrics(), logger
                            )
    return disputes_q


@pytest.mark.asyncio
async def test_match_records_verified_ok(bridge_env):
    q = await run_inspection(bridge_env, (TRUSTED, "ok"))
    row = bridge_env.get("0xtx1")
    assert row["status"] == STATUS_VERIFIED_OK
    assert json.loads(row["reported_json"])["amount"] == 100
    assert q.empty()  # nothing to dispute


@pytest.mark.asyncio
async def test_mismatch_records_pending_and_defers_dispute(bridge_env):
    """Even with a dispute threshold enabled (minor=1.0), Tier 1 must NOT queue a dispute."""
    q = await run_inspection(bridge_env, (TRUSTED, "ok"), reported=("0xaaa", "tellor1x", 999, 1))
    row = bridge_env.get("0xtx1")
    assert row["status"] == STATUS_MISMATCH_PENDING
    assert row["last_error"] == "tier1_mismatch"
    assert q.empty()  # G7 closed: single-check mode no longer fires the dispute


@pytest.mark.asyncio
async def test_fetch_failure_records_unverified_and_alerts(bridge_env):
    """G1 closed: RPC failure = persisted unverified row + Discord alert, not a silent skip."""
    with patch("layer_values_monitor.monitor.bridge_ledger_alert") as alert:
        q = await run_inspection(bridge_env, (None, "rpc_error"))
    row = bridge_env.get("0xtx1")
    assert row["status"] == STATUS_UNVERIFIED
    assert row["last_error"] == "rpc_error"
    alert.assert_called_once()
    assert "UNVERIFIED" in alert.call_args.args[0]
    assert q.empty()


@pytest.mark.asyncio
async def test_zero_struct_records_unverified_not_mismatch(bridge_env):
    """A lagging node's zero-struct must not read as a real record (trap #1)."""
    with patch("layer_values_monitor.monitor.bridge_ledger_alert"):
        await run_inspection(bridge_env, (None, "zero_struct"))
    assert bridge_env.get("0xtx1")["status"] == STATUS_UNVERIFIED


@pytest.mark.asyncio
async def test_unverified_alert_fires_once_per_tx_hash(bridge_env):
    """Catch-up replay of the same report must not re-alert (idempotency guard)."""
    with patch("layer_values_monitor.monitor.bridge_ledger_alert") as alert:
        await run_inspection(bridge_env, (None, "rpc_error"))
        await run_inspection(bridge_env, (None, "rpc_error"))
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
    strings against the checksummed env values the sweep writes into eth_deposits."""
    monkeypatch.setenv("TRBBRIDGE_CONTRACT_ADDRESS", CONTRACT.lower())
    await run_inspection(bridge_env, (TRUSTED, "ok"))
    assert bridge_env.get("0xtx1")["contract_address"] == CONTRACT
