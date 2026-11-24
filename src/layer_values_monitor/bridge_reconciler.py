"""Tier 2: in-process reconciliation of bridge deposit reports.

Tier 1 (inspect_trbbridge_reports in monitor.py) records a match immediately and leaves a
zero-struct or mismatch unverified for this task. This task periodically:

  a) re-reads EVERY `unverified` row each cycle, FOREVER — no retry cap, no expiry. The
     60s confirm-read discipline (shared get_bridge_verdict helper, confirm=True) decides good/bad;
     nothing but good/bad ends the retry loop,
  b) escalates anything still unverified near the 12-hour dispute deadline.

Terminal statuses (good, bad) are never rechecked; rows are kept for audit
(bridge volume is tiny).
"""

import asyncio
import json
import logging
import os
import time

from layer_values_monitor.bridge_ledger import (
    DEFAULT_RECONCILE_INTERVAL,
    DISPUTE_WINDOW_HOURS,
    STATUS_BAD,
    STATUS_GOOD,
    STATUS_UNVERIFIED,
    BridgeLedger,
    get_bridge_ledger,
)
from layer_values_monitor.bridge_networks import resolve_bridge_chain_id
from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.constants import DENOM
from layer_values_monitor.custom_types import DisputeCategory, Metrics, Msg
from layer_values_monitor.discord import bridge_ledger_alert
from layer_values_monitor.dispute import equality_dispute_category
from layer_values_monitor.trb_bridge import get_bridge_verdict, make_provider_builder

DESC_RESOLVED = "🌉 **BRIDGE REPORT RESOLVED**"
DESC_DISPUTED = "🌉 **BRIDGE REPORT DISPUTED**"
DESC_LATE_VERDICT = "🌉 **BRIDGE LATE VERDICT: BAD (dispute window missed)**"
DESC_ESCALATION = "🚨 **RPCs DOWN — BRIDGE REPORT ABOUT TO BE UNDISPUTABLE**"


def _equality_dispute_category(metrics: Metrics | None) -> DisputeCategory | None:
    """Resolve the equality dispute category the way inspect() does.

    is_disputable gates equality disputes on warning_threshold > 0, and the category is
    named by whichever threshold is set to 1.0. All-zero thresholds (the example/rollout
    config) mean disputes are DISABLED — return None.

    """
    if metrics is None or metrics.metric.lower() != "equality":
        return None
    if metrics.warning_threshold <= 0:
        return None  # dispute gate disabled (LVM equality semantics)
    return equality_dispute_category(metrics)


async def _recheck_row(
    row: dict,
    ledger: BridgeLedger,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
    chain_id: int,
    now: float | None = None,
    confirm_delay_s: float | None = None,
) -> None:
    """Re-verify one `unverified` row with the shared read/confirm verdict helper.

    Verdicts: ok -> good (+ resolved alert); bad -> bad (+ dispute if still inside the
    12h window, late-verdict alert otherwise); unavailable -> stay unverified and retry
    forever (this row was already alerted when it was recorded).
    """
    tx_hash = row["tx_hash"]
    contract = row["contract_address"]
    deposit_id = row["deposit_id"]
    reported = json.loads(row["reported_json"]) if row["reported_json"] else None
    if not contract or deposit_id is None or reported is None:
        return
    now = time.time() if now is None else now

    provider_builder = make_provider_builder(chain_id, logger=logger)
    verdict, _trusted = await get_bridge_verdict(
        provider_builder,
        contract,
        deposit_id,
        reported,
        confirm_delay_s=confirm_delay_s,
        logger=logger,
    )

    if verdict == "ok":
        ledger.set_status(tx_hash, STATUS_GOOD, error="recheck matched the on-chain deposit")
        bridge_ledger_alert(
            DESC_RESOLVED,
            {
                "Tx Hash": tx_hash,
                "Deposit ID": deposit_id,
                "QueryId": row["query_id"],
                "Detail": f"retried after {row['retries'] or 0} failed read(s); report matches the on-chain deposit",
            },
        )
        return

    if verdict == "bad":
        ledger.set_status(tx_hash, STATUS_BAD, error="confirm read still zero-struct/mismatch vs report")
        if now < row["report_ts"] + DISPUTE_WINDOW_HOURS * 3600:
            queued = await _queue_dispute(row, disputes_q, config_watcher, logger)
            if queued:
                bridge_ledger_alert(
                    DESC_DISPUTED,
                    {
                        "Tx Hash": tx_hash,
                        "Deposit ID": deposit_id,
                        "QueryId": row["query_id"],
                        "Detail": "confirm read confirms mismatch; dispute queued",
                    },
                )
        else:
            bridge_ledger_alert(
                DESC_LATE_VERDICT,
                {
                    "Tx Hash": tx_hash,
                    "Deposit ID": deposit_id,
                    "QueryId": row["query_id"],
                    "Reporter": row["reporter"] or "?",
                    "Detail": f"BAD, but the {DISPUTE_WINDOW_HOURS}h dispute window closed before a verdict was reached",
                },
            )
        return

    # "unavailable": RPC loss survives rotation; stay unverified and keep trying forever.
    ledger.set_status(tx_hash, STATUS_UNVERIFIED, error="rpc_error", bump_retries=True)


async def _queue_dispute(
    row: dict,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
) -> bool:
    """Queue a confirmed dispute using the existing category/fee logic. True when queued.

    The caller has already marked the row `bad` — a disabled-dispute config (threshold 0.0)
    still records the verdict, it just queues nothing.
    """
    from layer_values_monitor.dispute import determine_dispute_fee

    metrics = None
    if config_watcher is not None:
        try:
            metrics = config_watcher.get_metrics_for_query(row["query_id"], row["query_type"])
        except Exception as e:
            logger.error(f"bridge dispute: config lookup failed for {row['query_id'][:16]}...: {e}")

    category = _equality_dispute_category(metrics)
    if category is None:
        logger.info(f"bridge dispute {row['tx_hash'][:16]}: marked bad but disputes disabled (threshold 0.0)")
        return False

    fee = determine_dispute_fee(category, int(row["power"] or 0))
    await disputes_q.put(Msg(row["reporter"], row["query_id"], row["meta_id"], category, fee.__str__() + DENOM))
    logger.info(f"🌉 Bridge reconciler queued {category} dispute for {row['tx_hash'][:16]}... (fee {fee}{DENOM})")
    return True


async def check_deadlines(
    ledger: BridgeLedger,
    logger: logging.Logger,
    now: float | None = None,
    hours: float = DISPUTE_WINDOW_HOURS,
) -> None:
    """One-time escalation: still unverified ~10h in means the report is about to become undisputable."""
    now = time.time() if now is None else now

    for row in ledger.near_deadline(now=now, hours=hours):
        hours_left = max(0.0, (row["report_ts"] + hours * 3600 - now) / 3600)
        bridge_ledger_alert(
            DESC_ESCALATION,
            {
                "Tx Hash": row["tx_hash"],
                "Deposit ID": row["deposit_id"],
                "QueryId": row["query_id"],
                "Detail": f"all RPCs down; report unverified and about to become undisputable, {hours_left:.1f}h left",
            },
        )
        ledger.mark_escalated(row["tx_hash"])


async def run_reconcile_cycle(
    ledger: BridgeLedger,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
    interval: float | None = None,
    chain_id: int | None = None,
    now: float | None = None,
    confirm_delay_s: float | None = None,
) -> None:
    """One full reconciler pass: rechecks, then deadline escalation."""
    now = time.time() if now is None else now
    chain_id = chain_id if chain_id is not None else resolve_bridge_chain_id(logger=logger)
    if interval is None:
        interval = float(os.getenv("BRIDGE_RECONCILE_INTERVAL", str(DEFAULT_RECONCILE_INTERVAL)))

    due = ledger.due_for_recheck(now=now, interval=interval)
    if due:
        logger.info(f"bridge reconciler: rechecking {len(due)} row(s)")
    for row in due:
        try:
            await _recheck_row(
                row, ledger, disputes_q, config_watcher, logger, chain_id, now=now, confirm_delay_s=confirm_delay_s
            )
        except Exception as e:
            logger.error(f"bridge recheck failed for {row['tx_hash'][:16]}...: {e}")

    try:
        await check_deadlines(ledger, logger, now=now)
    except Exception as e:
        logger.error(f"bridge deadline check failed: {e}")


async def bridge_reconcile_loop(
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
    ledger: BridgeLedger | None = None,
    interval: float | None = None,
) -> None:
    """Long-running Tier 2 task (started from main.py alongside the queue handlers).

    Runs one cycle immediately on start (check-on-start rule), then every interval.
    """
    ledger = ledger if ledger is not None else get_bridge_ledger()
    if interval is None:
        interval = float(os.getenv("BRIDGE_RECONCILE_INTERVAL", str(DEFAULT_RECONCILE_INTERVAL)))
    logger.info(f"🌉 Bridge reconciler started (interval {interval:.0f}s, ledger: {ledger.path})")

    first = True
    while True:
        try:
            if not first:
                await asyncio.sleep(interval)
            first = False
            await run_reconcile_cycle(ledger, disputes_q, config_watcher, logger, interval=interval)
        except asyncio.CancelledError:
            logger.info("Bridge reconciler cancelled, shutting down")
            raise
        except Exception as e:
            # The loop itself must never die: one bad cycle is logged and retried next interval.
            logger.error(f"Bridge reconcile cycle failed: {e}")
