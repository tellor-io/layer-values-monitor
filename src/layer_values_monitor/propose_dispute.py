"""Propose dispute."""

import json
import subprocess
import time
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
    payfrom_bond: str,
) -> str | None:
    """Execute propose-dispute message using layer's binary."""
    cmd = [
        binary_path,
        "tx",
        "dispute",
        "propose-dispute",
        reporter,
        meta_id,
        query_id,
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
        "--gas-prices",
        "1loya",
        "--gas",
        "auto",
        "--gas-adjustment",
        "1.3",
        "-y",
        "--output",
        "json",
    ]

    time.sleep(5)
    try:
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            logger.error("Error calling dispute transaction in cli:", result.stderr)
            return None
        signed_tx = json.loads(result.stdout)
        code = signed_tx["code"]
        if code != 0:
            print(signed_tx)
            logger.error(f"failed to execute dispute msg: {signed_tx['raw_log']}")
            return None
        logger.info(f"dispute msg executed successfully: {signed_tx['txhash']}")
        return signed_tx["txhash"]
    except Exception as e:
        logger.error(f"failed to execute dispute msg: {e.__str__()}")
        return None


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


if __name__ == "__main__":
    import shutil

    tx_hash = propose_msg(
        binary_path=shutil.which("layerd"),
        reporter="tellor1atxszkp3ar3gshqklhafd6rtumndz73zwfe0dx",
        meta_id="1",
        query_id="0xasdk",
        dispute_category="warning",
        fee="1000000loya",
        key_name="alice",
        chain_id="layer-1",
        rpc="http://localhost:26657",
        kb="test",
        kdir="~/.layer",
        payfrom_bond="True",
    )
    print(tx_hash)
