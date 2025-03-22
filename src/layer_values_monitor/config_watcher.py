"""Module to watch and manage a live configuration."""

import asyncio
import time
import tomllib
from pathlib import Path
from typing import Any

from layer_values_monitor.logger import logger


class ConfigWatcher:
    """Class to watch and manage a live configuration."""

    def __init__(self, config_path: Path) -> None:
        """Initialize the configuration watcher."""
        self.config_path = config_path
        self.config = {}
        self.last_modified_time = 0
        self.reload_config()

    def reload_config(self) -> bool:
        """Reload config if modified, return True if reloaded."""
        current_mtime = self.config_path.stat().st_mtime
        if current_mtime > self.last_modified_time:
            with open(self.config_path, "rb") as f:
                data = tomllib.load(f)
                data = {k.lower(): v for k, v in data.items()}
                for key, value in data.items():
                    if isinstance(value, dict):
                        data[key.lower()] = {k.lower(): v for k, v in value.items()}
            self.config = data
            self.last_modified_time = current_mtime
            logger.info(f"Configuration reloaded at {time.strftime('%H:%M:%S')}")
            return True
        return False

    def get_config(self) -> dict[str, Any]:
        """Get the current configuration."""
        return self.config


async def watch_config(config_watcher: ConfigWatcher, check_interval: float = 5.0) -> None:
    """Watch the config file for changes and reload when modified."""
    while True:
        config_watcher.reload_config()
        await asyncio.sleep(check_interval)
