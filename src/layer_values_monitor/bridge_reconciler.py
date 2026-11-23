"""Tier 2: in-process reconciliation of bridge deposit reports.

Tier 1 (inspect_trbbridge_reports in monitor.py) reaches verdicts inline but only disputes
its own confirmed mismatches. This task periodically sweeps the ledger and:

  a) re-reads EVERY `unverified` row each cycle, FOREVER — no retry cap, no expiry. The
     60s confirm-read discipline (shared get_bridge_verdict helper) decides good/bad;
     nothing but good/bad ends the retry loop,
  b) sweeps the bridge's `depositId()` counter to journal every deposit ever made
     (gapless counter; structs written once, never deleted),
  c) alerts once when an eth deposit's Layer reporting window closes with no report,
  d) escalates anything still unverified near the 12-hour dispute deadline.

Terminal statuses (good, bad) are never rechecked; rows are kept for audit
(bridge volume is tiny).
"""

import asyncio
import json
import logging
import os
import time

from layer_values_monitor.bridge_ledger import (
    DEFAULT_LAYER_BLOCK_SECONDS,
    DEFAULT_MISSING_MAX_AGE_HOURS,
    DEFAULT_RECONCILE_INTERVAL,
    DEFAULT_REPORT_WINDOW_BLOCKS,
    DISPUTE_WINDOW_HOURS,
    STATUS_BAD,
    STATUS_GOOD,
    STATUS_UNVERIFIED,
    BridgeLedger,
    get_bridge_ledger,
)
from layer_values_monitor.bridge_networks import BRIDGE_CONTRACT_ENVS, resolve_bridge_chain_id, resolve_contract_address
from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.constants import DENOM
from layer_values_monitor.custom_types import DisputeCategory, Metrics, Msg
from layer_values_monitor.discord import bridge_ledger_alert
from layer_values_monitor.evm_connections import get_web3_connection
from layer_values_monitor.trb_bridge import (
    DEPOSITS_ABI,
    deposit_query_id,
    get_bridge_verdict,
    is_zero_struct,
    make_provider_builder,
    read_deposit_counter,
)

from web3 import Web3

DESC_RESOLVED = "🌉 **BRIDGE REPORT RESOLVED**"
DESC_DISPUTED = "🌉 **BRIDGE REPORT DISPUTED**"
DESC_LATE_VERDICT = "🌉 **BRIDGE LATE VERDICT: BAD (dispute window missed)**"
DESC_ESCALATION = "🚨 **RPCs DOWN — BRIDGE REPORT ABOUT TO BE UNDISPUTABLE**"
DESC_MISSING = "🌉 **BRIDGE REPORT MISSING**"

# Mainnet and Sepolia both produce ~12s PoS blocks — enough to age a deposit when its
# deposit block itself was pruned from the provider.
AVG_EVM_BLOCK_SECONDS = 12

# Bridge contract env var -> query type string (used to recompute queryIds for orphan alerts)
BRIDGE_QUERY_TYPES = {"TRBBRIDGE_CONTRACT_ADDRESS": "TRBBridge", "TRBBRIDGEV2_CONTRACT_ADDRESS": "TRBBridgeV2"}


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


def _query_type_for_contract(contract_address: str) -> str:
    """Map a bridge contract address (checksummed) back to its query type string."""
    for env_name, qtype in BRIDGE_QUERY_TYPES.items():
        addr = resolve_contract_address(env_name)
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


def _probe_deposit_struct(w3: Web3, contract: str, deposit_id: int) -> tuple:
    """Direct deposits(id) state read for the counter sweep. Raises on RPC failure."""
    bridge = w3.eth.contract(address=Web3.to_checksum_address(contract), abi=DEPOSITS_ABI)
    return bridge.functions.deposits(deposit_id).call()


def _deposit_block_ts(w3: Web3, block_number: int, logger: logging.Logger) -> float | None:
    """Deposit-block timestamp, estimated from the latest header when the read fails.

    A pruned provider raises (or omits the timestamp) for old blocks; the deposit's own
    block number still dates it well enough for the coarse missing-report aging.
    """
    try:
        raw_ts = w3.eth.get_block(block_number).get("timestamp")
        if raw_ts is not None:
            return float(raw_ts)
    except Exception as e:
        logger.debug(f"bridge deposit block {block_number} timestamp read failed ({e}); estimating from head")
    try:  # ~12s PoS slots: fine for age classification, not for exact windows
        head = w3.eth.get_block("latest")
        head_ts, head_num = head.get("timestamp"), head.get("number")
        if head_ts is None or head_num is None:
            return None
        return float(head_ts) - max(0, int(head_num) - block_number) * AVG_EVM_BLOCK_SECONDS
    except Exception:
        return None


def _record_deposit_state(ledger: BridgeLedger, w3: Web3, contract: str, deposit_id: int, details: tuple) -> bool:
    """Journal one deposits() struct into eth_deposits. True when newly recorded."""
    sender, layer_recipient, amount, tip, block_number = details
    reported = {
        "eth_address": str(sender).lower(),
        "layer_address": layer_recipient,
        "amount": int(amount),
        "tip": int(tip),
    }
    block_number = int(block_number)
    # deposit block timestamp anchors the missing-report window
    block_ts = _deposit_block_ts(w3, block_number, logging.getLogger(__name__))
    # eth_tx_hash is unknown from a state read; the journal keeps "" for it
    return ledger.record_eth_deposit(contract, deposit_id, "", block_number, reported, block_ts)


async def sweep_deposits(
    ledger: BridgeLedger, logger: logging.Logger, chain_id: int, w3: Web3 | None = None
) -> None:
    """Journal deposits by sweeping the gapless `depositId()` counter (no event logs).

    depositId() only advances on success (reverted deposits revert the increment too) and
    deposits(id) structs are never deleted. The counter is the LAST ISSUED id (deposit()
    writes deposits[depositId] after ++), so ids [floor, depositId()] inclusive are exactly
    the deposits ever made at this contract. `floor` covers the V1->V2 init seed: ids below
    the init read zero structs here, so the first run probes downward until the first zero.
    A counter DECREASE (reorg) is a silent no-op: the cursor stays and catches up.
    """
    if w3 is None:
        w3 = get_web3_connection(chain_id, required=False)
    if w3 is None:
        logger.warning("bridge deposit sweep: no eth RPC connection this cycle")
        return

    for env_name in BRIDGE_CONTRACT_ENVS:
        contract = resolve_contract_address(env_name, logger=logger)
        if not contract:
            continue
        contract = Web3.to_checksum_address(contract)
        floor_key = f"deposit_floor_{contract.lower()}"
        next_key = f"deposit_next_{contract.lower()}"

        try:
            counter = read_deposit_counter(w3, contract)
        except Exception as e:
            logger.warning(f"bridge deposit sweep {contract[:10]}..: depositId() read failed ({e})")
            continue

        floor_raw = ledger.get_meta(floor_key)
        if floor_raw is None:
            # First run: probe DOWNWARD from the counter (last issued id) until a zero
            # struct (the init floor). Cost is O(deposits since init), one-time. An RPC
            # error aborts the backfill without recording a floor, so a transient outage
            # can't truncate history.
            i = counter
            recorded = 0
            aborted = False
            while i >= 0:
                try:
                    details = _probe_deposit_struct(w3, contract, i)
                except Exception as e:
                    logger.warning(
                        f"bridge deposit backfill {contract[:10]}..: deposits({i}) failed ({e}); retry next cycle"
                    )
                    aborted = True
                    break
                if is_zero_struct(details):
                    break
                if _record_deposit_state(ledger, w3, contract, i, details):
                    recorded += 1
                i -= 1
            if aborted:
                continue
            floor = max(i + 1, 0)
            ledger.set_meta(floor_key, str(floor))
            ledger.set_meta(next_key, str(counter + 1))
            logger.info(
                f"bridge deposit backfill {contract[:10]}..: floor {floor}, {recorded} deposits recorded (counter {counter})"
            )
            continue

        next_id = int(ledger.get_meta(next_key) or floor_raw)
        if counter < next_id:
            # silent no-op: counter flat, or reorged below the cursor
            continue

        recorded = 0
        stopped_at = counter + 1
        for deposit_id in range(next_id, counter + 1):
            try:
                details = _probe_deposit_struct(w3, contract, deposit_id)
            except Exception as e:
                logger.warning(f"bridge deposit sweep {contract[:10]}..: deposits({deposit_id}) failed ({e})")
                stopped_at = deposit_id
                break
            if is_zero_struct(details):
                logger.warning(
                    f"bridge deposit sweep {contract[:10]}..: deposits({deposit_id}) zero struct above floor "
                    "— gapless counter assumption broken"
                )
                continue
            if _record_deposit_state(ledger, w3, contract, deposit_id, details):
                recorded += 1
        ledger.set_meta(next_key, str(stopped_at))
        if recorded:
            logger.info(
                f"bridge deposit sweep {contract[:10]}..: ids {next_id}-{stopped_at - 1}, {recorded} new deposits recorded"
            )


async def _layer_has_report(rest_url: str, query_id: str) -> bool:
    """Ask the Layer oracle module whether any micro-report exists for this queryId."""
    import aiohttp

    url = f"{rest_url.rstrip('/')}/layer/oracle/get_reportsby_qid/{query_id}"
    async with aiohttp.ClientSession() as sess:
        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            data = await resp.json(content_type=None)
    return bool(isinstance(data, dict) and data.get("microReports"))


async def check_missing_reports(ledger: BridgeLedger, logger: logging.Logger, now: float | None = None) -> None:
    """Alert once on eth deposits whose Layer reporting window closed with no report row.

    No alert before the on-chain reporting window (BRIDGE_REPORT_WINDOW_BLOCKS ×
    BRIDGE_LAYER_BLOCK_SECONDS) has closed — a report can still legally land — and the
    oracle REST is consulted first to catch reports the ledger never saw. Deposits older
    than BRIDGE_MISSING_REPORT_MAX_AGE_HOURS retire WITHOUT an alert: the check is about
    timeliness, and a fresh ledger's first backfill would otherwise alert on every old
    deposit whose report simply predates the ledger (e.g. V1 TRBBridge reports from
    before the TRBBridgeV2 transition).
    """
    now = time.time() if now is None else now
    window_blocks = float(os.getenv("BRIDGE_REPORT_WINDOW_BLOCKS", str(DEFAULT_REPORT_WINDOW_BLOCKS)))
    window_s = window_blocks * float(os.getenv("BRIDGE_LAYER_BLOCK_SECONDS", str(DEFAULT_LAYER_BLOCK_SECONDS)))
    max_age_h = float(os.getenv("BRIDGE_MISSING_REPORT_MAX_AGE_HOURS", str(DEFAULT_MISSING_MAX_AGE_HOURS)))
    max_age_s = max_age_h * 3600
    rest_url = os.getenv("LAYER_REST_URL") or ""

    for row in ledger.pending_missing_reports(now=now, window_s=window_s):
        anchor = row["block_ts"] if row["block_ts"] is not None else row["first_seen_ts"]
        if anchor + max_age_s <= now:
            ledger.resolve_missing_report(row["contract_address"], row["deposit_id"])
            age_d = (now - anchor) / 86_400
            logger.info(
                f"bridge deposit {row['deposit_id']}: {age_d:.1f}d old with no Layer report — "
                f"past the {max_age_h:.0f}h missing-report age, no alert"
            )
            continue
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
    """One full reconciler pass: rechecks, deposit sweep, missing-report check, escalation."""
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
        await sweep_deposits(ledger, logger, chain_id)
    except Exception as e:
        logger.error(f"bridge deposit sweep failed: {e}")

    try:
        await check_missing_reports(ledger, logger, now=now)
    except Exception as e:
        logger.error(f"bridge missing-report check failed: {e}")

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
