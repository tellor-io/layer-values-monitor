"""Module to watch and manage a live configuration."""

from __future__ import annotations

import asyncio
import time
import tomllib
from pathlib import Path

from layer_values_monitor.custom_types import Metrics
from layer_values_monitor.logger import logger


class ConfigWatcher:
    """Class to watch and manage a live configuration."""

    def __init__(self, config_path: Path) -> None:
        """Initialize the configuration watcher."""
        self.config_path = config_path
        self.global_defaults: dict[str, dict] = {}
        self.query_types: dict[str, dict] = {}
        self.query_configs: dict[str, dict[str, dict]] = {}
        self.last_modified_time = 0
        self.reload_config()

    def reload_config(self) -> bool:
        """Reload config if modified, return True if reloaded."""
        current_mtime = self.config_path.stat().st_mtime
        if current_mtime <= self.last_modified_time:
            return False

        with open(self.config_path, "rb") as f:
            data = tomllib.load(f)

        # Normalize all keys to lowercase once
        self.global_defaults = {
            metric_type.lower(): thresholds 
            for metric_type, thresholds in data.get("global_defaults", {}).items()
        }
        
        self.query_types = {
            qtype.lower(): info 
            for qtype, info in data.get("query_types", {}).items()
        }
        
        # Normalize query configs: queries[query_type][query_id] = config
        self.query_configs = {
            qtype.lower(): {qid.lower(): cfg for qid, cfg in queries.items()}
            for qtype, queries in data.get("queries", {}).items()
        }

        self._validate_config()
        self.last_modified_time = current_mtime
        logger.info(f"Configuration reloaded at {time.strftime('%H:%M:%S')}")
        return True

    def get_query_type_info(self, query_type: str) -> dict | None:
        """Get query type information (handler, metric, description)."""
        return self.query_types.get(query_type.lower())

    def is_supported_query_type(self, query_type: str) -> bool:
        """Check if query type is supported."""
        return query_type.lower() in self.query_types

    def uses_telliot_catalog(self, query_type: str) -> bool:
        """Check if query type uses telliot catalog for trusted values."""
        query_type_info = self.query_types.get(query_type.lower())
        return query_type_info.get("handler") == "telliot_feeds" if query_type_info else False

    def has_query_config(self, query_id: str, query_type: str) -> bool:
        """Check if query has specific configuration."""
        query_type_configs = self.query_configs.get(query_type.lower(), {})
        return query_id.lower() in query_type_configs

    def get_query_config(self, query_id: str, query_type: str) -> dict:
        """Get query-specific config (e.g., datafeed_ca, custom thresholds)."""
        query_type_configs = self.query_configs.get(query_type.lower(), {})
        return query_type_configs.get(query_id.lower(), {})

    def find_query_config(self, query_id: str) -> dict:
        """Find query config by searching all query types (when query_type unknown).
        
        Use this when you only have query_id and need to find its config.
        Returns empty dict if query not found in any type.
        """
        query_id_lower = query_id.lower()
        for query_type_configs in self.query_configs.values():
            if query_id_lower in query_type_configs:
                return query_type_configs[query_id_lower]
        return {}

    def get_metrics_for_query(self, query_id: str, query_type: str) -> Metrics | None:
        """Get complete metrics configuration with inheritance.
        
        Inheritance order: global_defaults[metric_type] <- query_specific_config
        """
        query_type_info = self.query_types.get(query_type.lower())
        if not query_type_info:
            logger.warning(f"Unknown query type '{query_type}'")
            return None

        metric_type = query_type_info.get("metric")
        if not metric_type:
            logger.error(f"Query type '{query_type}' missing 'metric' field")
            return None

        # Merge: global defaults + query-specific overrides
        base_config = self.global_defaults.get(metric_type, {})
        specific_config = self.get_query_config(query_id, query_type)
        merged = {**base_config, **specific_config}

        return Metrics(
            metric=metric_type,
            alert_threshold=merged.get("alert_threshold", 0.1),
            warning_threshold=merged.get("warning_threshold", 0.0),
            minor_threshold=merged.get("minor_threshold", 0.0),
            major_threshold=merged.get("major_threshold", 0.0),
            pause_threshold=merged.get("pause_threshold", 0.0),
        )

    def _validate_config(self) -> None:
        """Validate configuration structure."""
        # Check metric types
        for metric_type in ["percentage", "equality", "range"]:
            if metric_type not in self.global_defaults:
                logger.warning(f"Missing global defaults for metric type: {metric_type}")

        # Check query types have required fields
        for query_type, info in self.query_types.items():
            if "metric" not in info:
                logger.error(f"Query type '{query_type}' missing 'metric' field")
            if "handler" not in info:
                logger.error(f"Query type '{query_type}' missing 'handler' field")


async def watch_config(config_watcher: ConfigWatcher, check_interval: float = 5.0) -> None:
    """Watch the config file for changes and reload when modified."""
    while True:
        config_watcher.reload_config()
        await asyncio.sleep(check_interval)
