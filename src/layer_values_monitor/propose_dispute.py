"""Propose dispute."""

import json
import subprocess
from typing import Literal

from layer_values_monitor.logger import logger

DisputeCategory = Literal["warning", "minor", "major"]


def propose_msg(
    binary_path: str,
    reporter: str,
    query_id: str,
    meta_id: str,
    dispute_category: DisputeCategory,
    fee: str,
    key_name: str,
    chain_id: str,
    rpc: str,
    kb: str,
    kdir: str,
    payfrom_bond: bool,
) -> str | None:
    """Execute propose-dispute message using layer's binary."""
    cmd = [
        binary_path,
        "tx",
        "dispute",
        "propose-dispute",
        reporter,
        query_id,
        meta_id,
        dispute_category,
        fee,
        payfrom_bond,
        "--from",
        key_name,
        "--chain-id",
        chain_id,
        "--node",
        rpc,
        "--keyring-backend",
        kb,
        "--keyring-dir",
        kdir,
        "-y",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        logger.error(f"failed to execute dispute msg: {e.__str__()}")
    if result.returncode != 0:
        print("Error sending transaction:", result.stderr)
        return None
    else:
        signed_tx = json.loads(result.stdout)
        print("Transaction Hash: ", signed_tx["txhash"])
        return signed_tx["txhash"]


def determine_dispute_category(
    diff: float,
    # should be already manually sorted
    category_thresholds: dict[DisputeCategory, float],
) -> DisputeCategory | None:
    """Determine dispute category based on difference value and category thresholds."""
    # Return the most severe category whose threshold is met
    for category, threshold in category_thresholds.items():
        if threshold == 0:
            continue
        if diff >= threshold:
            return category

    return None


def determine_dispute_fee(
    category: DisputeCategory,
    reporter_power: int,
) -> int:
    """Calculate dispute fee based on category and reporter power."""
    if category == "warning":
        percentage = 0.01
    elif category == "minor":
        percentage = 0.05
    else:
        percentage = 1

    return int((reporter_power * 1_000_000) * percentage)
