"""Send messages using Discord."""

import os

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
