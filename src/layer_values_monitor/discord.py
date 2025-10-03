"""Send messages using Discord."""

import os
from typing import Any

import click
from discordwebhook import Discord


def generic_alert(msg: str) -> None:
    """Send a Discord message via webhook."""
    send_discord_msg(msg)
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


def send_discord_msg(msg: str) -> None:
    """Send Discord alert."""
    MONITOR_NAME = os.getenv("MONITOR_NAME")
    message = f"❗{MONITOR_NAME} Found Something❗\n"
    get_alert_bot_1().post(content=message + msg)
    try:
        get_alert_bot_2().post(content=message + msg)
    except Exception as e:
        click.echo(f"alert bot 2 not used? {e}")
        pass
    try:
        get_alert_bot_3().post(content=message + msg)
    except Exception as e:
        click.echo(f"alert bot 3 not used? {e}")
        pass
    click.echo("Alerts sent!")
    return


def format_difference(diff: float, metric: str) -> str:
    """Format difference value based on metric type."""
    if metric.lower() == "percentage":
        return f"{diff * 100:.2f}%"
    elif metric.lower() == "range":
        return f"{diff:.4f}"
    return f"{diff}"


def format_values(reported: Any, trusted: Any) -> str:
    """Format reported and trusted values for display."""
    if isinstance(reported, dict):
        reported_display = "\n".join([f"  - {k}: {v}" for k, v in reported.items()])
        trusted_display = "\n".join([f"  - {k}: {v}" for k, v in trusted.items()])
        return f"**Reported:**\n{reported_display}\n**Trusted:**\n{trusted_display}"
    return f"**Reported:** {reported}\n**Trusted:** {trusted}"


def build_alert_message(
    query_info: str,
    value_display: str,
    diff_str: str,
    reporter: str,
    power: str,
    tx_hash: str,
) -> str:
    """Build the formatted Discord alert message."""
    reporter_short = f"{reporter[:8]}...{reporter[-6:]}" if len(reporter) > 14 else reporter
    return (
        f"**ALERTABLE VALUE DETECTED**\n"
        f"**Asset:** {query_info}\n"
        f"{value_display}\n"
        f"**Difference:** {diff_str}\n"
        f"**Reporter:** {reporter_short}\n"
        f"**Power:** {power}\n"
        f"**Tx Hash:** {tx_hash}"
    )
