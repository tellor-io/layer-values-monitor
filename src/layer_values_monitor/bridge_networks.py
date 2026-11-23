"""Built-in TRB bridge contract defaults, keyed by the Tellor Layer chain being monitored.

The bridge contract addresses are deterministic per deployment: tellor-1 always talks to the
mainnet TokenBridgeV2, and layertest-5 always talks to the Sepolia TokenBridge pair.
Requiring TRBBRIDGE*_CONTRACT_ADDRESS in .env added nothing but a way to be silently
misconfigured, so they are baked in here. Every other chain (layertest-8, local devnets)
has no built-in and still requires the env vars, which remain overrides where a built-in
does exist.

Verified against Etherscan (2026-11-23, getsourcecode ContractName):
  chain 1        0x6ec401744008f4B018Ed9A36f76e6629799Ee50E  TokenBridgeV2 (only bridge on mainnet)
  chain 11155111 0x62733e63499a25E35844c91275d4c3bdb159D29d  TokenBridge   (v1)
  chain 11155111 0x55355157703A44f7516FBB831333317E98944e32  TokenBridgeV2
"""

import logging
import os
from typing import Any

from layer_values_monitor.evm_connections import validate_rpc_connection

BRIDGE_CONTRACT_ENVS = ("TRBBRIDGE_CONTRACT_ADDRESS", "TRBBRIDGEV2_CONTRACT_ADDRESS")

_MAINNET_BRIDGE = "0x6ec401744008f4B018Ed9A36f76e6629799Ee50E"
_SEPOLIA_BRIDGE_V1 = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
_SEPOLIA_BRIDGE_V2 = "0x55355157703A44f7516FBB831333317E98944e32"

# Exact-match only, keyed by Layer chain ID (the required CHAIN_ID env var). Do NOT widen
# with prefix rules: the Sepolia pair belongs to layertest-5 alone — other testnets are
# expected to point at their own bridge deployments via the env vars.
_BUILTIN_DEFAULTS = {
    "tellor-1": {
        "TRBBRIDGE_CONTRACT_ADDRESS": _MAINNET_BRIDGE,
        "TRBBRIDGEV2_CONTRACT_ADDRESS": _MAINNET_BRIDGE,
        "evm_chain_id": 1,
    },
    "layertest-5": {
        "TRBBRIDGE_CONTRACT_ADDRESS": _SEPOLIA_BRIDGE_V1,
        "TRBBRIDGEV2_CONTRACT_ADDRESS": _SEPOLIA_BRIDGE_V2,
        "evm_chain_id": 11155111,
    },
}

# Announce a built-in default only once per env var per process (reconciler re-resolves each cycle).
_announced: set[str] = set()


def _builtin_for_layer_chain() -> dict | None:
    """Return the built-in bridge defaults block for the Layer chain in CHAIN_ID, or None."""
    return _BUILTIN_DEFAULTS.get(os.getenv("CHAIN_ID", "").strip().lower())


def _log_once(logger: logging.Logger, key: str, message: str) -> None:
    if key not in _announced:
        _announced.add(key)
        logger.info(message)


def resolve_contract_address(env_name: str, logger: Any = None) -> str | None:
    """Effective bridge contract address for one env var: env override, then built-in default.

    Returns None only when the Layer chain has no built-in default and the env var is unset;
    callers treat that the same way they treated a missing env var before.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    raw = os.getenv(env_name)
    if raw:
        return raw

    builtin = _builtin_for_layer_chain()
    if builtin is not None and env_name in builtin:
        addr = builtin[env_name]
        _log_once(
            logger,
            f"addr:{env_name}",
            f"{env_name} not set; using built-in default for Layer chain '{os.getenv('CHAIN_ID', '').strip()}': {addr}",
        )
        return addr
    return None


def _configured_bridge_rpc_urls(chain_id: int) -> list[str]:
    """Return the RPC URLs the bridge path would use for this chain (same lookup order as get_web3_connection)."""
    urls_value = os.getenv(f"EVM_RPC_URLS_{chain_id}") or os.getenv("EVM_RPC_URLS")
    if urls_value:
        return [url.strip() for url in urls_value.split(",") if url.strip()]
    infura_key = os.getenv("INFURA_API_KEY")
    if infura_key:
        infura_urls = {
            1: f"https://mainnet.infura.io/v3/{infura_key}",
            11155111: f"https://sepolia.infura.io/v3/{infura_key}",
        }
        if chain_id in infura_urls:
            return [infura_urls[chain_id]]
    return []


def validate_bridge_rpc(logger: Any = None) -> None:
    """Startup gate: probe every configured bridge RPC and FATAL on a chain-ID mismatch.

    A wrong-chain endpoint is not a performance problem, it is a correctness one: a contract
    with a compatible deposits() signature at the same address on the wrong chain would yield
    a wrong trusted value and could dispute a correct report. Runtime detection
    (get_web3_connection) only warns, so gate it here while startup can still refuse.

    Semantics:
      - detected chain ID != resolved bridge chain ID -> ValueError (fatal)
      - endpoint unreachable at startup -> warning only (a transient RPC outage must not
        stop the non-bridge monitoring; runtime retries still apply)
      - no URL configured (TelliotConfig fallback will be tried at runtime) -> warning only
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    chain_id = resolve_bridge_chain_id(logger=logger)
    urls = _configured_bridge_rpc_urls(chain_id)
    if not urls:
        logger.warning(
            f"🌉 No EVM_RPC_URLS_{chain_id} / EVM_RPC_URLS / INFURA_API_KEY configured for bridge reads; "
            "runtime will fall back to TelliotConfig endpoints"
        )
        return

    mismatches = []
    for url in urls:
        is_valid, error_msg, detected = validate_rpc_connection(url, f"TRB bridge RPC (chain {chain_id})", logger)
        if not is_valid:
            logger.warning(f"🌉 Bridge RPC probe failed for {url} at startup: {error_msg} (continuing; runtime retries)")
        elif detected != chain_id:
            mismatches.append(f"{url} reports chain ID {detected}")

    if mismatches:
        raise ValueError(
            f"🌉 Bridge RPC chain ID mismatch: TRBBRIDGE_CHAIN_ID resolves to {chain_id} but "
            + "; ".join(mismatches)
            + f". Fix EVM_RPC_URLS_{chain_id} / EVM_RPC_URLS"
            + " (or TRBBRIDGE_CHAIN_ID) before monitoring bridge reports."
        )

    # One clear success line; the per-URL probe successes are already in the log.
    logger.info(f"🌉 Bridge RPC validation passed: all {len(urls)} endpoint(s) on chain {chain_id}")


def resolve_bridge_chain_id(logger: Any = None) -> int:
    """Effective EVM chain ID for bridge reads: TRBBRIDGE_CHAIN_ID override, then built-in default.

    Falls back to 1 (mainnet) when neither the override nor a built-in default applies,
    preserving the historical code default.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    raw = os.getenv("TRBBRIDGE_CHAIN_ID")
    if raw:
        return int(raw)

    builtin = _builtin_for_layer_chain()
    if builtin is not None:
        chain_id = int(builtin["evm_chain_id"])
        _log_once(
            logger,
            "evm_chain_id",
            f"TRBBRIDGE_CHAIN_ID not set; using built-in default {chain_id} for Layer chain "
            f"'{os.getenv('CHAIN_ID', '').strip()}'",
        )
        return chain_id
    return 1
