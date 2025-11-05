"""Module to watch and manage a live configuration."""

from __future__ import annotations

import asyncio
import time
import tomllib
from pathlib import Path
from typing import Any

from layer_values_monitor.custom_types import Metrics
from layer_values_monitor.logger import logger


class ConfigWatcher:
    """Class to watch and manage a live configuration."""

    def __init__(self, config_path: Path) -> None:
        """Initialize the configuration watcher."""
        self.config_path = config_path
        self.config = {}
        self.global_defaults = {}  # Global threshold defaults
        self.query_types = {}  # Query type definitions
        self.query_configs = {}  # Organized query configurations
        self.last_modified_time = 0
        self.reload_config()

    def reload_config(self) -> bool:
        """Reload config if modified, return True if reloaded."""
        current_mtime = self.config_path.stat().st_mtime
        if current_mtime > self.last_modified_time:
            with open(self.config_path, "rb") as f:
                data = tomllib.load(f)

            # Extract global defaults
            self.global_defaults = data.get("global_defaults", {})

            # Extract query types and configs
            self.query_types = data.get("query_types", {})
            self.query_configs = data.get("queries", {})

            # Keep backward compatibility for old config format
            self.config = {k.lower(): v for k, v in data.items()}
            for key, value in self.config.items():
                if isinstance(value, dict):
                    self.config[key.lower()] = {k.lower(): v for k, v in value.items()}

            # Validate config
            self._validate_config()

            self.last_modified_time = current_mtime
            logger.info(f"Configuration reloaded at {time.strftime('%H:%M:%S')}")
            return True
        return False

    def get_config(self) -> dict[str, Any]:
        """Get the current configuration (backward compatibility)."""
        return self.config

    def get_query_type_info(self, query_type: str) -> dict | None:
        """Get query type information."""
        query_type_lower = query_type.lower()
        return self.query_types.get(query_type_lower)

    def is_supported_query_type(self, query_type: str) -> bool:
        """Check if query type is supported."""
        query_type_lower = query_type.lower()
        return query_type_lower in self.query_types

    def uses_telliot_catalog(self, query_type: str) -> bool:
        """Check if query type uses telliot catalog for trusted values.

        Returns True if the query type's handler is 'telliot_feeds', meaning it
        requires queries to be in the telliot catalog. Returns False for custom
        handlers like 'evm_call' and 'trb_bridge' that have their own inspection logic.
        """
        query_type_info = self.query_types.get(query_type.lower())
        if not query_type_info:
            return False

        handler = query_type_info.get("handler", "")
        return handler == "telliot_feeds"

    def get_metrics_for_query(self, query_id: str, query_type: str) -> Metrics | None:
        """Get complete metrics configuration with inheritance."""
        # Get query type info
        query_type_info = self.query_types.get(query_type.lower())
        if not query_type_info:
            logger.warning(f"No query type info found for '{query_type}'")
            return None

        metric_type = query_type_info["metric"]

        # Start with global defaults for this metric type
        base_config = self.global_defaults.get(metric_type, {})

        # Get specific query config
        query_type_configs = self.query_configs.get(query_type.lower(), {})
        specific_config = query_type_configs.get(query_id.lower(), {})

        # Merge configurations (specific overrides base)
        merged_config = {**base_config, **specific_config}

        return Metrics(
            metric=metric_type,
            alert_threshold=merged_config.get("alert_threshold", 0.1),
            warning_threshold=merged_config.get("warning_threshold", 0.25),
            minor_threshold=merged_config.get("minor_threshold", 0.99),
            major_threshold=merged_config.get("major_threshold", 0.0),
            pause_threshold=merged_config.get("pause_threshold", 0.2),
        )

    def _validate_config(self) -> None:
        """Validate configuration structure."""
        required_metric_types = ["percentage", "equality", "range"]
        for metric_type in required_metric_types:
            if metric_type not in self.global_defaults:
                logger.warning(f"Missing global defaults for metric type: {metric_type}")
            else:
                logger.debug(f"Found global defaults for {metric_type}: {self.global_defaults[metric_type]}")

        # Validate query types have required fields
        for query_type, info in self.query_types.items():
            logger.debug(f"Validating query type '{query_type}': {info}")
            if "metric" not in info:
                logger.error(f"Query type '{query_type}' missing 'metric' field")
            if "handler" not in info:
                logger.error(f"Query type '{query_type}' missing 'handler' field")


async def watch_config(config_watcher: ConfigWatcher, check_interval: float = 5.0) -> None:
    """Watch the config file for changes and reload when modified."""
    while True:
        config_watcher.reload_config()
        await asyncio.sleep(check_interval)
