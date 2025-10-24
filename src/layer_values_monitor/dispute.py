"""Propose dispute."""

import asyncio
import json
import logging
import os
import subprocess
import time

from layer_values_monitor.custom_types import DisputeCategory, Msg
from layer_values_monitor.logger import logger


def get_disputer_address(binary_path: str, key_name: str, kb: str, kdir: str) -> str | None:
    """Get the disputer address for the given key name."""
    try:
        cmd = [
            binary_path,
            "keys",
            "show",
            key_name,
            "--keyring-backend",
            kb,
            "--keyring-dir",
            kdir,
            "--address",
            "--output",
            "json",
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        if result.returncode != 0:
            logger.error(f"Failed to get disputer address: {result.stderr}")
            return None
        
        address_data = json.loads(result.stdout)
        return address_data.get("address")
        
    except subprocess.TimeoutExpired:
        logger.error("Getting disputer address timed out")
        return None
    except Exception as e:
        logger.error(f"Error getting disputer address: {e}")
        return None


def validate_keyring_config(binary_path: str, key_name: str, kb: str, kdir: str) -> bool:
    """Validate that the key exists in the keyring before attempting disputes."""
    try:
        cmd = [
            binary_path,
            "keys",
            "list",
            "--keyring-backend",
            kb,
            "--keyring-dir",
            kdir,
            "--output",
            "json",
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        if result.returncode != 0:
            logger.error(f"Failed to list keys: {result.stderr}")
            return False
        
        keys_data = json.loads(result.stdout)
        key_names = [key.get("name", "") for key in keys_data]
        
        if key_name not in key_names:
            logger.error(f"Key '{key_name}' not found in keyring. Available keys: {key_names}")
            return False
        
        logger.info(f"✅ Key '{key_name}' found in keyring")
        return True
        
    except subprocess.TimeoutExpired:
        logger.error("Keyring validation timed out")
        return False
    except Exception as e:
        logger.error(f"Error validating keyring: {e}")
        return False


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
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode != 0:
            logger.error(f"Error calling dispute transaction in cli: {result.stderr}")
            return None
        signed_tx = json.loads(result.stdout)
        code = signed_tx["code"]
        if code != 0:
            print(signed_tx)
            logger.error(f"failed to execute dispute msg: {signed_tx['raw_log']}")
            return None
        logger.info(f"dispute msg executed successfully: {signed_tx['txhash']}")
        return signed_tx["txhash"]
    except subprocess.TimeoutExpired:
        logger.error(f"Dispute transaction timed out after 30 seconds. Command: {' '.join(cmd)}")
        return None
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


async def process_disputes(
    disputes_q: asyncio.Queue,
    binary_path: str,
    key_name: str,
    chain_id: str,
    rpc: str,
    kb: str,
    kdir: str,
    payfrom_bond: bool,
    logger: logging,
) -> None:
    """Process dispute messages from queue and submit them to the blockchain."""
    logger.info(f"💡 Dispute processor started with key: {key_name}, keyring: {kb}, dir: {kdir}")
    
    # Validate keyring configuration before starting
    if not validate_keyring_config(binary_path, key_name, kb, kdir):
        logger.error("❌ Keyring validation failed. Auto-disputing will not work.")
        # Keep the processor running but just log when disputes come in
        while True:
            try:
                dispute: Msg = await disputes_q.get()
                disputes_q.task_done()
                if dispute is None:
                    continue
                logger.warning(f"⚠️ DISPUTE SKIPPED - {key_name} Keyring validation failed, no dispute will be sent for query {dispute.query_id[:16]}... (reporter: {dispute.reporter})")
                # Send Discord alert for skipped dispute due to keyring issues
                from layer_values_monitor.discord import generic_alert
                monitor_name = os.getenv("MONITOR_NAME", "LVM")
                skipped_msg = f"**{monitor_name}** ⚠️ **DISPUTE SKIPPED - KEYRING ISSUE**\n"
                skipped_msg += f"**Query ID:** {dispute.query_id}\n"
                skipped_msg += f"**Reporter:** {dispute.reporter}\n"
                skipped_msg += f"**Category:** {dispute.category}\n"
                skipped_msg += f"**Fee:** {dispute.fee}\n"
                skipped_msg += f"**Reason:** Keyring validation failed - check binary path and key configuration"
                logger.warning(f"Dispute skipped alert:\n{skipped_msg}")
                generic_alert(skipped_msg)
            except Exception as e:
                logger.error(f"❌ Error in disabled dispute processor: {e}", exc_info=True)
        return
    
    logger.info("✅ Dispute processing enabled - disputes will be submitted to blockchain")
    
    while True:
        try:
            dispute: Msg = await disputes_q.get()
            disputes_q.task_done()
            if dispute is None:
                continue
            time.sleep(2)
            logger.info(
                f"sending a dispute msg to layer:\n \
                        Reporter: {dispute.reporter}\n \
                        Query ID: {dispute.query_id} \
                        "
            )
            result = propose_msg(
                binary_path=binary_path,
                key_name=key_name,
                chain_id=chain_id,
                rpc=rpc,
                kb=kb,
                kdir=kdir,
                reporter=dispute.reporter,
                query_id=dispute.query_id,
                meta_id=dispute.meta_id,
                dispute_category=dispute.category,
                fee=dispute.fee,
                payfrom_bond=str(payfrom_bond),
            )
            if result:
                logger.info(f"✅ Dispute transaction successful: {result}")
                # Send Discord alert for successful dispute
                from layer_values_monitor.discord import generic_alert
                monitor_name = os.getenv("MONITOR_NAME", "LVM")
                success_msg = f"**{monitor_name}** ✅ **DISPUTE SUBMITTED SUCCESSFULLY**\n"
                success_msg += f"**Query ID:** {dispute.query_id}\n"
                success_msg += f"**Reporter:** {dispute.reporter}\n"
                success_msg += f"**Category:** {dispute.category}\n"
                success_msg += f"**Fee:** {dispute.fee}\n"
                success_msg += f"**Dispute Tx Hash:** {result}"
                logger.info(f"Dispute success alert:\n{success_msg}")
                generic_alert(success_msg)
            else:
                logger.warning(f"⚠️ Dispute transaction failed for query {dispute.query_id}")
                # Send Discord alert for failed dispute
                from layer_values_monitor.discord import generic_alert
                monitor_name = os.getenv("MONITOR_NAME", "LVM")
                failure_msg = f"**{monitor_name}** ❌ **DISPUTE SUBMISSION FAILED**\n"
                failure_msg += f"**Query ID:** {dispute.query_id}\n"
                failure_msg += f"**Reporter:** {dispute.reporter}\n"
                failure_msg += f"**Category:** {dispute.category}\n"
                failure_msg += f"**Fee:** {dispute.fee}\n"
                failure_msg += f"**Reason:** Transaction failed - check logs for details"
                logger.warning(f"Dispute failure alert:\n{failure_msg}")
                generic_alert(failure_msg)
        except Exception as e:
            logger.error(f"❌ Error processing dispute: {e}", exc_info=True)
            # Continue processing other disputes even if one fails


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
