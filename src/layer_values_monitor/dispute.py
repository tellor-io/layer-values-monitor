"""Propose dispute."""

import asyncio
import json
import logging
import subprocess
import time
from typing import Any

from layer_values_monitor.custom_types import DisputeCategory, Msg
from layer_values_monitor.logger import console_logger, logger
from layer_values_monitor.utils import remove_0x_prefix


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

        console_logger.info(f"✅ Key '{key_name}' found in keyring")
        return True

    except subprocess.TimeoutExpired:
        logger.error("Keyring validation timed out")
        return False
    except Exception as e:
        logger.error(f"Error validating keyring: {e}")
        return False


async def propose_msg(
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
    """Execute propose-dispute message using layer's binary as an unordered transaction.

    Follows Cosmos SDK 0.53+ unordered transaction pattern:
    https://docs.cosmos.network/v0.53/build/architecture/adr-070-unordered-account
    """
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
        "--unordered",
        "--timeout-duration",
        "30s",
        "-y",
        "--output",
        "json",
    ]

    logger.debug(f"Executing dispute transaction command: {' '.join(cmd)}")
    await asyncio.sleep(3)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        
        if proc.returncode != 0:
            logger.error(f"Error calling dispute transaction in cli: {stderr.decode()}")
            return None
        signed_tx = json.loads(stdout.decode())
        code = signed_tx["code"]
        if code != 0:
            print(signed_tx)
            logger.error(f"failed to execute dispute msg: {signed_tx['raw_log']}")
            return None
        logger.info(f"dispute msg executed successfully: {signed_tx['txhash']}")
        return signed_tx["txhash"]
    except asyncio.TimeoutError:
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


def is_disputable(
    metric: str, alert_threshold: float, dispute_threshold: float, reported_value: Any, trusted_value: Any, logger: logging
) -> tuple[bool, bool, float] | tuple[None, None, None]:
    """Determine if a value is disputable based on comparison with a trusted value using specified metrics and thresholds."""
    if metric.lower() == "percentage":
        percent_diff: float = (reported_value - trusted_value) / trusted_value
        percent_diff = abs(percent_diff)
        logger.debug(f"percent diff: {percent_diff}, reported value: {reported_value} - trusted value: {trusted_value}")

        # Handle None values for thresholds - but don't override valid thresholds
        if alert_threshold is None:
            alert_threshold = 0.0
        if dispute_threshold is None:
            dispute_threshold = 0.0

        if dispute_threshold == 0:
            return percent_diff >= alert_threshold, False, percent_diff
        return percent_diff >= alert_threshold, percent_diff >= dispute_threshold, percent_diff

    if metric.lower() == "equality":
        # Convert bytes to hex for readable logs
        reported_hex = reported_value.hex() if isinstance(reported_value, bytes) else reported_value
        trusted_hex = trusted_value.hex() if isinstance(trusted_value, bytes) else trusted_value
        logger.info(f"checking equality of values, reported value: {reported_hex}, trusted value: {trusted_hex}")

        # Handle None values for thresholds
        if alert_threshold is None:
            alert_threshold = 0.0
        if dispute_threshold is None:
            dispute_threshold = 0.0

        # Handle structured data (dicts) vs simple values
        if isinstance(reported_value, dict) and isinstance(trusted_value, dict):
            is_not_equal = reported_value != trusted_value
        else:
            # For simple values, use string comparison
            is_not_equal = remove_0x_prefix(str(reported_value)).lower() != remove_0x_prefix(str(trusted_value).lower())

        # Convert to float for consistency
        diff_value = float(is_not_equal)

        # For equality metric, if values differ and dispute_threshold > 0, it's disputable
        alertable = is_not_equal and alert_threshold > 0
        disputable = is_not_equal and dispute_threshold > 0

        logger.debug(
            f"Equality logic - is_not_equal: {is_not_equal}, "
            f"alert_threshold: {alert_threshold}, dispute_threshold: {dispute_threshold}, "
            f"alertable: {alertable}, disputable: {disputable}"
        )

        return alertable, disputable, diff_value

    if metric.lower() == "range":
        diff = float(abs(reported_value - trusted_value))

        # Handle None values for thresholds
        if alert_threshold is None:
            alert_threshold = 0.0
        if dispute_threshold is None:
            dispute_threshold = 0.0

        if dispute_threshold == 0:
            return diff >= alert_threshold, False, diff
        return diff >= alert_threshold, diff >= dispute_threshold, diff

    logger.error(f"unsupported metric: {metric}")
    return None, None, None


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
    logger.info(f"Dispute processor: key={key_name}, keyring={kb}, dir={kdir}")

    # Validate keyring configuration before starting
    if not validate_keyring_config(binary_path, key_name, kb, kdir):
        console_logger.error("❌ Keyring validation failed - disputes disabled")
        logger.error("❌ Keyring validation failed. Auto-disputing will not work.")
        # Keep the processor running but just log when disputes come in
        while True:
            try:
                dispute: Msg = await disputes_q.get()
                disputes_q.task_done()
                if dispute is None:
                    continue
                logger.warning(
                    f"⚠️ DISPUTE SKIPPED - {key_name} Keyring validation failed, "
                    f"no dispute will be sent for query {dispute.query_id[:16]}... "
                    f"(reporter: {dispute.reporter})"
                )
                # Send Discord alert for skipped dispute due to keyring issues
                from layer_values_monitor.discord import generic_alert

                skipped_msg = f"**Query ID:** {dispute.query_id}\n"
                skipped_msg += f"**Reporter:** {dispute.reporter}\n"
                skipped_msg += f"**Category:** {dispute.category}\n"
                skipped_msg += f"**Fee:** {dispute.fee}\n"
                skipped_msg += "**Reason:** Keyring validation failed - check binary path and key configuration"
                logger.warning(f"Dispute skipped alert:\n{skipped_msg}")
                generic_alert(skipped_msg, description="⚠️ **DISPUTE TX FAIL - KEYRING ISSUE**")
            except Exception as e:
                logger.error(f"❌ Error in disabled dispute processor: {e}", exc_info=True)
        return

    console_logger.info("✅ Auto disputer ready")

    while True:
        try:
            dispute: Msg = await disputes_q.get()
            disputes_q.task_done()
            if dispute is None:
                continue
            await asyncio.sleep(2)
            logger.info(
                f"sending a dispute msg to layer:\n \
                        Reporter: {dispute.reporter}\n \
                        Query ID: {dispute.query_id} \
                        "
            )
            result = await propose_msg(
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

                success_msg = f"**Query ID:** {dispute.query_id}\n"
                success_msg += f"**Reporter:** {dispute.reporter}\n"
                success_msg += f"**Category:** {dispute.category}\n"
                success_msg += f"**Fee:** {dispute.fee}\n"
                success_msg += f"**Dispute Tx Hash:** {result}"
                logger.info(f"Dispute success alert:\n{success_msg}")
                generic_alert(success_msg, description="✅ **DISPUTE SUBMITTED SUCCESSFULLY**")
            else:
                logger.warning(f"⚠️ Dispute transaction failed for query {dispute.query_id}")
                # Send Discord alert for failed dispute
                from layer_values_monitor.discord import generic_alert

                failure_msg = f"**Query ID:** {dispute.query_id}\n"
                failure_msg += f"**Reporter:** {dispute.reporter}\n"
                failure_msg += f"**Category:** {dispute.category}\n"
                failure_msg += f"**Fee:** {dispute.fee}\n"
                failure_msg += "**Reason:** Transaction failed - check logs for details"
                logger.warning(f"Dispute failure alert:\n{failure_msg}")
                generic_alert(failure_msg, description="❌ **DISPUTE SUBMISSION FAILED**")
        except Exception as e:
            logger.error(f"❌ Error processing dispute: {e}", exc_info=True)
            # Continue processing other disputes even if one fails