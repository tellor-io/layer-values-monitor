"""Send messages using Discord."""

import logging
import os
from typing import Any

from layer_values_monitor.logger import console_logger

from discordwebhook import Discord


def generic_alert(msg: str, description: str = None) -> None:
    """Send a Discord message via webhook.

    Args:
        msg: The message content to send
        description: Optional description/alert type (e.g., "Found Something", "DISPUTE SKIPPED")

    """
    send_discord_msg(msg, description=description)
    return


def get_alert_bot_1() -> Discord:
    """Read the Discord webhook url from the environment."""
    DISCORD_WEBHOOK_URL_1 = os.getenv("DISCORD_WEBHOOK_URL_1")
    if DISCORD_WEBHOOK_URL_1 is None:
        raise Exception("At least one DISCORD_WEBHOOK_URL is required.")
    alert_bot_1 = Discord(url=DISCORD_WEBHOOK_URL_1)
    return alert_bot_1


def get_alert_bot_2() -> Discord:
    """Read the Discord webhook url from the environment."""
    return Discord(url=os.getenv("DISCORD_WEBHOOK_URL_2"))


def get_alert_bot_3() -> Discord:
    """Read the Discord webhook url from the environment."""
    return Discord(url=os.getenv("DISCORD_WEBHOOK_URL_3"))


def send_discord_msg(msg: str, description: str = None) -> None:
    """Send Discord alert.

    Args:
        msg: The message content to send
        description: Optional description/alert type line. If None, uses "❗Found Something❗"

    """
    # Get logger for file logging (not console)
    file_logger = logging.getLogger(__name__)

    MONITOR_NAME = os.getenv("MONITOR_NAME", "LVM")

    # First line: Monitor name only (bold)
    first_line = f"LVM: **{MONITOR_NAME}**\n"

    # Second line: Description/alert type, then message content
    if description:
        second_line = f"{description}\n{msg}"
        display_description = description
    else:
        # Default description for regular alerts
        second_line = f"❗**FOUND SOMETHING**❗\n{msg}"
        display_description = "❗**FOUND SOMETHING**❗"

    # Add separator line at the end of message for better readability
    separator = "\n" + "─" * 50 + "\n"
    full_message = first_line + second_line + separator

    get_alert_bot_1().post(content=full_message)
    try:
        get_alert_bot_2().post(content=full_message)
    except Exception as e:
        # Log to file only, not terminal
        file_logger.debug(f"Alert bot 2 not used: {e}")
        pass
    try:
        get_alert_bot_3().post(content=full_message)
    except Exception as e:
        # Log to file only, not terminal
        file_logger.debug(f"Alert bot 3 not used: {e}")
        pass

    # Clean console output - just show alert sent + description
    console_logger.info(f"Discord alert sent! {display_description}")
    return


def format_difference(diff: float, metric: str) -> str:
    """Format difference value based on metric type."""
    if metric.lower() == "percentage":
        return f"{diff * 100:.2f}%"
    elif metric.lower() == "range":
        return f"{diff:.4f}"
    return f"{diff}"


def format_values(reported: Any, trusted: Any, query_type: str = None) -> str:
    """Format reported and trusted values for display.

    Args:
        reported: The reported value
        trusted: The trusted value
        query_type: Optional query type (e.g., "EVMCall") for special formatting

    """
    if isinstance(reported, dict):
        reported_display = "\n".join([f"  {k}: {v}" for k, v in reported.items()])
        trusted_display = "\n".join([f"  {k}: {v}" for k, v in trusted.items()])
        return f"**Reported:**\n{reported_display}\n**Trusted:**\n{trusted_display}"

    # Format EVMCall bytes values as hex strings for better readability
    if query_type == "EVMCall" and isinstance(reported, bytes) and isinstance(trusted, bytes):
        reported_hex = "0x" + reported.hex()
        trusted_hex = "0x" + trusted.hex()
        # Also try to decode as uint256 if it's 32 bytes (common case)
        reported_decoded = ""
        trusted_decoded = ""
        if len(reported) == 32:
            try:
                from eth_abi import decode

                (reported_int,) = decode(["uint256"], reported)
                reported_decoded = f" ({reported_int})"
            except Exception:
                pass
        if len(trusted) == 32:
            try:
                from eth_abi import decode

                (trusted_int,) = decode(["uint256"], trusted)
                trusted_decoded = f" ({trusted_int})"
            except Exception:
                pass
        return f"**Reported:** {reported_hex}{reported_decoded}\n**Trusted:** {trusted_hex}{trusted_decoded}"

    return f"**Reported:** {reported}\n**Trusted:** {trusted}"


def build_alert_message(
    query_info: str,
    value_display: str,
    diff_str: str,
    reporter: str,
    power: str,
    tx_hash: str,
    query_type: str = None,
    disputer_info: str = None,
    level: str = None,
) -> str:
    """Build the formatted Discord alert message."""
    # Determine if this is a spot price query
    is_spot_price = query_type == "SpotPrice" or "/" in query_info

    # Build the message components
    components = []

    # Add Asset field only for spot price queries
    if is_spot_price:
        components.append(f"**Asset:** {query_info}")

    # Add QueryType field
    if query_type:
        components.append(f"**QueryType:** {query_type}")

    # Add Level field if available
    if level:
        components.append(f"**Level:** {level}")

    # Add the rest of the fields
    components.extend(
        [
            value_display,
            f"**Difference:** {diff_str}",
            f"**Reporter:** {reporter}",
            f"**Power:** {power}",
            f"**Tx Hash:** {tx_hash}",
        ]
    )

    # Add Disputer field if available
    if disputer_info:
        components.append(f"**Disputer:** {disputer_info}")

    return "\n".join(components)
