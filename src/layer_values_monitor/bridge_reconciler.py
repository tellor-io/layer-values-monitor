"""Tier 2: in-process reconciliation of bridge deposit reports.

Tier 1 (inspect_trbbridge_reports in monitor.py) records verdicts but never disputes.
This task periodically sweeps the ledger and:

  a) re-verifies `unverified` / `mismatch_pending` rows anchored at `finalized`,
  b) disputes mismatches a second check confirms — a SECOND, different RPC provider when one
     is configured, otherwise a same-endpoint re-read; a mismatch aged past
     BRIDGE_NO_RPC_DISPUTE_HOURS disputes on its last anchored read if no re-check is possible,
  c) sweeps the bridge's Deposit event logs to detect orphans (eth deposit with no
     Layer report) and reports referencing a deposit the log never emitted,
  d) escalates anything still unresolved near the 12-hour dispute deadline.

Terminal statuses (verified_ok, disputed, resolved_lag, expired_unresolved,
unverifiable) are never rechecked; rows are kept for audit (bridge volume is tiny).
"""

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable

from layer_values_monitor.bridge_ledger import (
    DEFAULT_LAYER_BLOCK_SECONDS,
    DEFAULT_NO_LOG_GRACE,
    DEFAULT_NO_RPC_DISPUTE_HOURS,
    DEFAULT_RECONCILE_INTERVAL,
    DEFAULT_REPORT_WINDOW_BLOCKS,
    DEFAULT_SWEEP_CHUNK_BLOCKS,
    DEFAULT_SWEEP_LOOKBACK_HOURS,
    DEFAULT_UNVERIFIABLE_RETRIES,
    DISPUTE_WINDOW_HOURS,
    STATUS_DISPUTED,
    STATUS_EXPIRED_UNRESOLVED,
    STATUS_MISMATCH_PENDING,
    STATUS_RESOLVED_LAG,
    STATUS_UNVERIFIABLE,
    STATUS_VERIFIED_OK,
    BridgeLedger,
    get_bridge_ledger,
)
from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.constants import DENOM
from layer_values_monitor.custom_types import DisputeCategory, Metrics, Msg
from layer_values_monitor.discord import bridge_ledger_alert
from layer_values_monitor.evm_connections import get_secondary_connection, get_web3_connection
from layer_values_monitor.trb_bridge import (
    decode_deposit_log,
    deposit_event_topic,
    deposit_query_id,
    fetch_deposit,
    make_provider_builder,
)

from web3 import Web3

BRIDGE_CONTRACT_ENVS = ("TRBBRIDGE_CONTRACT_ADDRESS", "TRBBRIDGEV2_CONTRACT_ADDRESS")
BRIDGE_QUERY_TYPES = {"TRBBRIDGE_CONTRACT_ADDRESS": "TRBBridge", "TRBBRIDGEV2_CONTRACT_ADDRESS": "TRBBridgeV2"}

DESC_UNRESOLVED = "🌉 **BRIDGE REPORT UNRESOLVED**"
DESC_RESOLVED = "🌉 **BRIDGE REPORT RESOLVED**"
DESC_UNVERIFIABLE = "🌉 **BRIDGE REPORT UNVERIFIABLE**"
DESC_MISSING = "🌉 **DEPOSIT MISSING LAYER REPORT**"


def _trusted_dict(deposit: tuple) -> dict:
    return {
        "eth_address": deposit[0],
        "layer_address": deposit[1],
        "amount": deposit[2],
        "tip": deposit[3],
    }


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
    if metrics.warning_threshold == 1.0:
        return "warning"
    if metrics.minor_threshold == 1.0:
        return "minor"
    if metrics.major_threshold == 1.0:
        return "major"
    return None


def _fixed_provider(w3: Web3) -> Callable[[int], Web3]:
    """Return a provider builder that always yields the same Web3 connection (ignores attempt)."""

    def builder(_attempt: int) -> Web3:
        return w3

    return builder


def _query_type_for_contract(contract_address: str) -> str:
    """Map a bridge contract address (checksummed) back to its query type string."""
    for env_name, qtype in BRIDGE_QUERY_TYPES.items():
        addr = os.getenv(env_name)
        if addr and Web3.to_checksum_address(addr) == contract_address:
            return qtype
    # No configured contract matches (env rotated/removed after the row was recorded):
    # V2 is the live default, but the alert's QueryId may then be computed with the wrong typeString.
    logging.getLogger(__name__).warning(
        f"bridge query-type lookup: no env match for contract {contract_address}; assuming TRBBridgeV2"
    )
    return "TRBBridgeV2"


async def _recheck_row(
    row: dict,
    ledger: BridgeLedger,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
    chain_id: int,
) -> None:
    """Re-verify one non-terminal ledger row against an anchored primary read (+ secondary)."""
    tx_hash = row["tx_hash"]
    contract = row["contract_address"]
    deposit_id = row["deposit_id"]
    reported = json.loads(row["reported_json"]) if row["reported_json"] else None
    if not contract or deposit_id is None or reported is None:
        return

    max_retries = int(os.getenv("BRIDGE_UNVERIFIABLE_RETRIES", str(DEFAULT_UNVERIFIABLE_RETRIES)))
    primary_builder = make_provider_builder(chain_id, logger=logger)

    # Anchored re-read on the primary (hardened: retry + rotation + finalized fallback)
    deposit, kind = await fetch_deposit(
        primary_builder, contract, deposit_id, anchor="finalized", sanity=True, logger=logger
    )

    if kind == "ok" and deposit is not None:
        trusted = _trusted_dict(deposit)
        if trusted == reported:
            prev_status = row["status"]
            ledger.set_status(tx_hash, STATUS_VERIFIED_OK)
            if prev_status == STATUS_MISMATCH_PENDING:
                bridge_ledger_alert(
                    DESC_RESOLVED,
                    {"Tx Hash": tx_hash, "Deposit ID": deposit_id, "Status": "mismatch cleared on anchored recheck"},
                )
            return

        # Primary still says mismatch — second check before disputing: different provider if
        # configured, otherwise same-endpoint re-read (single-RPC deployments still dispute).
        secondary_w3 = get_secondary_connection(chain_id)
        if secondary_w3 is not None:
            secondary_builder = _fixed_provider(secondary_w3)
        else:
            logger.warning(f"bridge recheck {tx_hash[:16]}: no secondary provider; second check on same endpoint")
            secondary_builder = primary_builder

        dep2, kind2 = await fetch_deposit(
            secondary_builder, contract, deposit_id, anchor="finalized", sanity=True, logger=logger
        )
        if kind2 != "ok" or dep2 is None:
            # Second read unavailable: aged mismatches dispute on the anchored primary confirmation.
            if await _aged_dispute(row, ledger, disputes_q, config_watcher, logger, f"second read unavailable ({kind2})"):
                return
            logger.warning(f"bridge recheck {tx_hash[:16]}: second read failed ({kind2}); deferring")
            ledger.set_status(tx_hash, row["status"], error=f"second read {kind2}", bump_retries=True)
            return

        sec = _trusted_dict(dep2)
        if sec == reported:
            # Second read agrees with the report: the earlier read was lagging.
            logger.info(f"bridge recheck {tx_hash[:16]}: secondary matched report — resolved as provider lag")
            ledger.set_status(tx_hash, STATUS_RESOLVED_LAG, error="secondary matched report (lag cleared)")
            return
        if sec == trusted:
            # Second check agrees on the same non-reported value: dispute.
            await _queue_dispute(row, ledger, disputes_q, config_watcher, logger)
            return
        # The two reads disagree with each other — inconclusive, try again next cycle.
        logger.warning(f"bridge recheck {tx_hash[:16]}: providers disagree; no dispute this cycle")
        ledger.set_status(tx_hash, row["status"], error="providers disagree", bump_retries=True)
        return

    # Re-read failed (zero_struct / rpc_error)
    if row["status"] == STATUS_MISMATCH_PENDING and kind in ("rpc_error", "zero_struct"):
        # Mismatch seen once, no usable re-read since — RPC loss, or a deposit that keeps
        # reading as zero struct (the fake-deposit signature): age out to a dispute on the
        # anchored evidence, never to unverifiable while a mismatch stands.
        if await _aged_dispute(row, ledger, disputes_q, config_watcher, logger, f"no usable re-read ({kind})"):
            return
        ledger.set_status(tx_hash, row["status"], error=kind, bump_retries=True)
        return
    new_retries = (row["retries"] or 0) + 1
    if new_retries >= max_retries:
        ledger.set_status(tx_hash, STATUS_UNVERIFIABLE, error=kind, bump_retries=True)
        bridge_ledger_alert(
            DESC_UNVERIFIABLE,
            {
                "Tx Hash": tx_hash,
                "Deposit ID": deposit_id,
                "QueryId": row["query_id"],
                "Detail": (
                    f"deposit still not readable after {new_retries} rechecks ({kind}) — flag for humans, not disputed"
                ),
            },
        )
    else:
        ledger.set_status(tx_hash, row["status"], error=kind, bump_retries=True)


async def _queue_dispute(
    row: dict,
    ledger: BridgeLedger,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
    note: str = "double-confirmed mismatch",
) -> None:
    """Queue the confirmed dispute using the existing category/fee logic."""
    from layer_values_monitor.dispute import determine_dispute_fee

    metrics = None
    if config_watcher is not None:
        try:
            metrics = config_watcher.get_metrics_for_query(row["query_id"], row["query_type"])
        except Exception as e:
            logger.error(f"bridge dispute: config lookup failed for {row['query_id'][:16]}...: {e}")

    category = _equality_dispute_category(metrics)
    if category is None:
        # Alert-only config (thresholds 0.0): row stays pending until a config change or expiry.
        logger.info(f"bridge dispute {row['tx_hash'][:16]}: mismatch confirmed but disputes disabled (threshold 0.0)")
        return

    fee = determine_dispute_fee(category, int(row["power"] or 0))
    await disputes_q.put(Msg(row["reporter"], row["query_id"], row["meta_id"], category, fee.__str__() + DENOM))
    ledger.set_status(row["tx_hash"], STATUS_DISPUTED, error=f"{note} ({category} dispute queued)")
    logger.info(f"🌉 Bridge reconciler queued {category} dispute for {row['tx_hash'][:16]}... (fee {fee}{DENOM})")


async def _aged_dispute(
    row: dict,
    ledger: BridgeLedger,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
    note: str,
) -> bool:
    """Return True (and queue the dispute) when a detected mismatch aged out without re-confirmation.

    Only for mismatch_pending rows older than BRIDGE_NO_RPC_DISPUTE_HOURS: when no second read
    is possible anymore (RPC loss / secondary dead), dispute on the aged evidence instead of
    letting a fake deposit expire undisputed at the end of the dispute window.
    """
    hours = float(os.getenv("BRIDGE_NO_RPC_DISPUTE_HOURS", str(DEFAULT_NO_RPC_DISPUTE_HOURS)))
    if row["status"] != STATUS_MISMATCH_PENDING or hours <= 0:
        return False
    if (time.time() - float(row["report_ts"])) < hours * 3600:
        return False
    logger.warning(f"bridge recheck {row['tx_hash'][:16]}: {note}; disputing on evidence aged >{hours:.0f}h")
    await _queue_dispute(row, ledger, disputes_q, config_watcher, logger, note=note)
    return True


def _block_at_or_after(w3: Web3, target_ts: int, logger: logging.Logger) -> int:
    """Binary-search a block number whose timestamp is >= target_ts (first run sweep start)."""
    try:
        latest = w3.eth.block_number
    except Exception as e:
        logger.error(f"bridge sweep: cannot read latest block: {e}")
        return 0
    lo, hi = 1, latest
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            ts = w3.eth.get_block(mid)["timestamp"]
        except Exception as e:
            logger.error(f"bridge sweep: get_block({mid}) failed: {e}")
            return latest
        if ts < target_ts:
            lo = mid + 1
        else:
            hi = mid
    return lo


async def sweep_deposit_logs(
    ledger: BridgeLedger, logger: logging.Logger, chain_id: int, w3: Web3 | None = None
) -> None:
    """Pull Deposit event logs from the last cursor position (chunked, lookback-bounded).

    The cursor lives in the ledger meta table; the first run starts at the block closest to
    BRIDGE_SWEEP_LOOKBACK_HOURS ago so a long LVM outage backfills without rescanning history.
    """
    if w3 is None:
        w3 = get_web3_connection(chain_id, required=False)
    if w3 is None:
        logger.warning("bridge log sweep: no eth RPC connection this cycle")
        return

    lookback_s = float(os.getenv("BRIDGE_SWEEP_LOOKBACK_HOURS", str(DEFAULT_SWEEP_LOOKBACK_HOURS))) * 3600
    chunk = int(os.getenv("BRIDGE_SWEEP_CHUNK_BLOCKS", str(DEFAULT_SWEEP_CHUNK_BLOCKS)))

    try:
        target_block = w3.eth.get_block("finalized")["number"]
    except Exception:
        target_block = w3.eth.block_number  # providers without a finalized tag

    topic0 = deposit_event_topic()

    for env_name in BRIDGE_CONTRACT_ENVS:
        contract = os.getenv(env_name)
        if not contract:
            continue
        contract = Web3.to_checksum_address(contract)
        cursor_key = f"sweep_cursor_{contract.lower()}"
        start_ts_key = f"sweep_start_ts_{contract.lower()}"

        cursor = ledger.get_meta(cursor_key)
        if cursor is None:
            latest_ts = w3.eth.get_block("latest")["timestamp"]
            start = _block_at_or_after(w3, int(latest_ts - lookback_s), logger)
            first_block = start
            ledger.set_meta(start_ts_key, str(int(w3.eth.get_block(start)["timestamp"])))
        else:
            first_block = int(cursor) + 1

        if first_block > target_block:
            continue
        last_block = min(target_block, first_block + chunk - 1)

        try:
            logs = w3.eth.get_logs(
                {"address": contract, "topics": [topic0], "fromBlock": first_block, "toBlock": last_block}
            )
        except Exception as e:
            # Provider get_logs range cap hit — cursor stays, same range retried next cycle.
            logger.warning(f"bridge log sweep {contract[:10]}..: get_logs({first_block}, {last_block}) failed ({e})")
            continue

        recorded = 0
        for log in logs:
            decoded = decode_deposit_log(log)
            if decoded is None:
                continue
            eth_tx = log.get("transactionHash") if isinstance(log, dict) else getattr(log, "transactionHash", None)
            eth_tx = eth_tx.hex() if hasattr(eth_tx, "hex") else str(eth_tx or "")
            reported = {
                "eth_address": decoded["sender"],
                "layer_address": decoded["recipient"],
                "amount": decoded["amount"],
                "tip": decoded["tip"],
            }
            block_number = log["blockNumber"] if isinstance(log, dict) else log.blockNumber
            try:  # deposit block timestamp anchors the Layer reporting window
                block_ts: float | None = float(w3.eth.get_block(int(block_number))["timestamp"])
            except Exception:
                block_ts = None
            if ledger.record_eth_deposit(
                contract, decoded["deposit_id"], eth_tx, int(block_number), reported, block_ts
            ):
                recorded += 1

        ledger.set_meta(cursor_key, str(last_block))
        logger.info(
            f"bridge log sweep {contract[:10]}..: blocks {first_block}-{last_block}, {recorded} new deposits recorded"
        )


async def _layer_has_report(rest_url: str, query_id: str) -> bool:
    """Ask the Layer oracle module whether any micro-report exists for this queryId."""
    import aiohttp

    url = f"{rest_url.rstrip('/')}/layer/oracle/get_reportsby_qid/{query_id}"
    async with aiohttp.ClientSession() as sess:
        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            data = await resp.json(content_type=None)
    return bool(isinstance(data, dict) and data.get("microReports"))


async def check_orphans_and_missing(ledger: BridgeLedger, logger: logging.Logger, now: float | None = None) -> None:
    """Alert on eth deposits with no Layer report, and reports with no Deposit log (one-time alerts)."""
    now = time.time() if now is None else now
    window_blocks = float(os.getenv("BRIDGE_REPORT_WINDOW_BLOCKS", str(DEFAULT_REPORT_WINDOW_BLOCKS)))
    window_s = window_blocks * float(os.getenv("BRIDGE_LAYER_BLOCK_SECONDS", str(DEFAULT_LAYER_BLOCK_SECONDS)))
    no_log_grace = float(os.getenv("BRIDGE_NO_LOG_GRACE", str(DEFAULT_NO_LOG_GRACE)))
    rest_url = os.getenv("LAYER_REST_URL") or ""

    # A deposit is only actionable once the on-chain reporting window (registry dataspec
    # ReportBlockWindow) has closed: before that, a report can still legally land.
    for row in ledger.pending_missing_reports(now=now, window_s=window_s):
        qtype = _query_type_for_contract(row["contract_address"])
        qid = deposit_query_id(row["deposit_id"], qtype)
        detail = f"no Layer report within {int(window_blocks)}-block reporting window"
        if rest_url:
            try:
                if await _layer_has_report(rest_url, qid):
                    ledger.resolve_missing_report(row["contract_address"], row["deposit_id"])
                    logger.info(f"bridge deposit {row['deposit_id']}: late report found on oracle; no missing alert")
                    continue
            except Exception as e:
                detail += f"; oracle REST unconfirmed ({e})"
        if ledger.mark_missing_report(row["contract_address"], row["deposit_id"]):
            bridge_ledger_alert(
                DESC_MISSING,
                {
                    "Deposit ID": row["deposit_id"],
                    "Contract": row["contract_address"],
                    "Eth Tx": row["eth_tx_hash"] or "?",
                    "QueryId": qid,
                    "Detail": detail,
                },
            )

    # Layer reports whose deposit the event log never emitted (only where the sweep covers them)
    for env_name in BRIDGE_CONTRACT_ENVS:
        contract = os.getenv(env_name)
        if not contract:
            continue
        contract = Web3.to_checksum_address(contract)  # rows store the checksummed form
        start_ts = ledger.get_meta(f"sweep_start_ts_{contract.lower()}")
        if start_ts is None:
            continue  # sweep hasn't run; it doesn't cover this range yet
        for row in ledger.rows_without_log(contract, float(start_ts), now=now, grace_s=no_log_grace):
            ledger.set_status(row["tx_hash"], STATUS_UNVERIFIABLE, error="no Deposit event within sweep window")
            bridge_ledger_alert(
                DESC_UNVERIFIABLE,
                {
                    "Tx Hash": row["tx_hash"],
                    "Deposit ID": row["deposit_id"],
                    "QueryId": row["query_id"],
                    "Detail": "report references a deposit the event log never emitted (within lookback)",
                },
            )


async def check_deadlines(
    ledger: BridgeLedger,
    logger: logging.Logger,
    now: float | None = None,
    hours: float = DISPUTE_WINDOW_HOURS,
) -> None:
    """One-time escalation near the dispute deadline, then expire unresolved rows at the deadline."""
    now = time.time() if now is None else now

    for row in ledger.near_deadline(now=now, hours=hours):
        hours_left = max(0.0, (row["report_ts"] + hours * 3600 - now) / 3600)
        bridge_ledger_alert(
            DESC_UNRESOLVED,
            {
                "Tx Hash": row["tx_hash"],
                "Deposit ID": row["deposit_id"],
                "QueryId": row["query_id"],
                "Status": row["status"],
                "Detail": f"unresolved, {hours_left:.1f}h left in dispute window",
            },
        )
        ledger.mark_escalated(row["tx_hash"])

    for row in ledger.expired(now=now, hours=hours):
        ledger.set_status(row["tx_hash"], STATUS_EXPIRED_UNRESOLVED)
        logger.warning(f"bridge report {row['tx_hash'][:16]}... expired unresolved ({row['status']})")


async def run_reconcile_cycle(
    ledger: BridgeLedger,
    disputes_q: asyncio.Queue,
    config_watcher: ConfigWatcher | None,
    logger: logging.Logger,
    interval: float | None = None,
    chain_id: int | None = None,
    now: float | None = None,
) -> None:
    """One full reconciler pass: rechecks, log sweep, orphan/missing checks, deadline handling."""
    now = time.time() if now is None else now
    chain_id = chain_id if chain_id is not None else int(os.getenv("TRBBRIDGE_CHAIN_ID", "1"))
    if interval is None:
        interval = float(os.getenv("BRIDGE_RECONCILE_INTERVAL", str(DEFAULT_RECONCILE_INTERVAL)))

    due = ledger.due_for_recheck(now=now, interval=interval)
    if due:
        logger.info(f"bridge reconciler: rechecking {len(due)} row(s)")
    for row in due:
        try:
            await _recheck_row(row, ledger, disputes_q, config_watcher, logger, chain_id)
        except Exception as e:
            logger.error(f"bridge recheck failed for {row['tx_hash'][:16]}...: {e}")

    try:
        await sweep_deposit_logs(ledger, logger, chain_id)
    except Exception as e:
        logger.error(f"bridge Deposit log sweep failed: {e}")

    try:
        await check_orphans_and_missing(ledger, logger, now=now)
    except Exception as e:
        logger.error(f"bridge orphan/missing-report check failed: {e}")

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
    """Long-running Tier 2 task (started from main.py alongside the queue handlers)."""
    ledger = ledger if ledger is not None else get_bridge_ledger()
    if interval is None:
        interval = float(os.getenv("BRIDGE_RECONCILE_INTERVAL", str(DEFAULT_RECONCILE_INTERVAL)))
    logger.info(f"🌉 Bridge reconciler started (interval {interval:.0f}s, ledger: {ledger.path})")

    while True:
        try:
            await asyncio.sleep(interval)
            await run_reconcile_cycle(ledger, disputes_q, config_watcher, logger, interval=interval)
        except asyncio.CancelledError:
            logger.info("Bridge reconciler cancelled, shutting down")
            raise
        except Exception as e:
            # The loop itself must never die: one bad cycle is logged and retried next interval.
            logger.error(f"Bridge reconcile cycle failed: {e}")
