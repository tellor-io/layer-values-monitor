"""Module to watch and manage a live configuration."""

import asyncio
import time
import tomllib
from pathlib import Path
from typing import Any

from layer_values_monitor.custom_types import Metrics
from layer_values_monitor.logger import logger


class ConfigWatcher:
    """Class to watch and manage a live configuration."""

    def __init__(self, config_path: Path, threshold_config: "ThresholdConfig | None" = None) -> None:
        """Initialize the configuration watcher."""
        self.config_path = config_path
        self.config = {}
        self.global_defaults = {}  # Global threshold defaults
        self.query_types = {}  # Query type definitions
        self.query_configs = {}  # Organized query configurations
        self.last_modified_time = 0
        self.threshold_config = threshold_config  # Fallback for old configs
        logger.info(f"CONFIG DEBUG: Initializing ConfigWatcher with path: {config_path}")
        self.reload_config()

    def reload_config(self) -> bool:
        """Reload config if modified, return True if reloaded."""
        current_mtime = self.config_path.stat().st_mtime
        if current_mtime > self.last_modified_time:
            logger.info("CONFIG DEBUG: Config file modified, reloading...")
            with open(self.config_path, "rb") as f:
                data = tomllib.load(f)

            logger.info(f"CONFIG DEBUG: Raw config data keys: {list(data.keys())}")

            # Extract global defaults
            self.global_defaults = data.get("global_defaults", {})
            logger.info(f"CONFIG DEBUG: Global defaults loaded: {self.global_defaults}")

            # Extract query types and configs
            self.query_types = data.get("query_types", {})
            self.query_configs = data.get("queries", {})
            logger.info(f"CONFIG DEBUG: Query types loaded: {list(self.query_types.keys())}")
            logger.info(f"CONFIG DEBUG: Query configs loaded: {list(self.query_configs.keys())}")

            # Keep backward compatibility for old config format
            self.config = {k.lower(): v for k, v in data.items()}
            for key, value in self.config.items():
                if isinstance(value, dict):
                    self.config[key.lower()] = {k.lower(): v for k, v in value.items()}

            logger.info(f"CONFIG DEBUG: Backward compatibility config keys: {list(self.config.keys())}")

            # Validate config
            self._validate_config()

            self.last_modified_time = current_mtime
            logger.info(f"CONFIG DEBUG: Configuration reloaded successfully at {time.strftime('%H:%M:%S')}")
            return True
        else:
            logger.debug("CONFIG DEBUG: Config file unchanged, skipping reload")
        return False

    def get_config(self) -> dict[str, Any]:
        """Get the current configuration (backward compatibility)."""
        return self.config

    def get_query_type_info(self, query_type: str) -> dict | None:
        """Get query type information."""
        query_type_lower = query_type.lower()
        result = self.query_types.get(query_type_lower)
        logger.debug(f"CONFIG DEBUG: get_query_type_info('{query_type}') -> {result}")
        return result

    def is_supported_query_type(self, query_type: str) -> bool:
        """Check if query type is supported."""
        query_type_lower = query_type.lower()
        is_supported = query_type_lower in self.query_types
        logger.debug(f"CONFIG DEBUG: is_supported_query_type('{query_type}') -> {is_supported}")
        if not is_supported:
            logger.debug(f"CONFIG DEBUG: Available query types: {list(self.query_types.keys())}")
        return is_supported

    def uses_telliot_catalog(self, query_type: str) -> bool:
        """Check if query type uses telliot catalog for trusted values.

        Returns True if the query type's handler is 'telliot_feeds', meaning it
        requires queries to be in the telliot catalog. Returns False for custom
        handlers like 'evm_call' and 'trb_bridge' that have their own inspection logic.
        """
        query_type_info = self.query_types.get(query_type.lower())
        if not query_type_info:
            logger.debug(f"CONFIG DEBUG: No query type info found for '{query_type}'")
            return False

        handler = query_type_info.get("handler", "")
        uses_catalog = handler == "telliot_feeds"
        logger.debug(
            f"CONFIG DEBUG: uses_telliot_catalog('{query_type}') -> handler='{handler}', uses_catalog={uses_catalog}"
        )
        return uses_catalog

    def get_metrics_for_query(self, query_id: str, query_type: str) -> Metrics | None:
        """Get complete metrics configuration with inheritance."""
        logger.debug(f"CONFIG DEBUG: get_metrics_for_query('{query_id[:16]}...', '{query_type}')")

        # Get query type info
        query_type_info = self.query_types.get(query_type.lower())
        if not query_type_info:
            logger.warning(f"CONFIG DEBUG: No query type info found for '{query_type}'")
            return None

        logger.debug(f"CONFIG DEBUG: Query type info: {query_type_info}")
        metric_type = query_type_info["metric"]
        logger.debug(f"CONFIG DEBUG: Metric type: {metric_type}")

        # Start with global defaults for this metric type
        base_config = self.global_defaults.get(metric_type, {})

        # If no global defaults and we have a ThresholdConfig fallback, use it
        if not base_config and self.threshold_config:
            logger.debug(f"CONFIG DEBUG: No global defaults for {metric_type}, using ThresholdConfig fallback")
            if metric_type == "percentage":
                base_config = {
                    "alert_threshold": self.threshold_config.percentage_alert or 0.1,
                    "warning_threshold": self.threshold_config.percentage_warning or 0.25,
                    "minor_threshold": self.threshold_config.percentage_minor or 0.99,
                    "major_threshold": self.threshold_config.percentage_major or 0.0,
                    "pause_threshold": self.threshold_config.pause_threshold or 0.2,
                }
            elif metric_type == "equality":
                base_config = {
                    "alert_threshold": self.threshold_config.equality_alert or 1.0,
                    "warning_threshold": self.threshold_config.equality_warning or 0.0,
                    "minor_threshold": self.threshold_config.equality_minor or 0.0,
                    "major_threshold": self.threshold_config.equality_major or 0.0,
                    "pause_threshold": 0.0,  # Not applicable for equality
                }
            elif metric_type == "range":
                base_config = {
                    "alert_threshold": self.threshold_config.range_alert or 100.0,
                    "warning_threshold": self.threshold_config.range_warning or 200.0,
                    "minor_threshold": self.threshold_config.range_minor or 500.0,
                    "major_threshold": self.threshold_config.range_major or 1000.0,
                    "pause_threshold": self.threshold_config.pause_threshold or 0.0,
                }

        logger.debug(f"CONFIG DEBUG: Base config from global defaults: {base_config}")

        # Get specific query config
        query_type_configs = self.query_configs.get(query_type.lower(), {})
        specific_config = query_type_configs.get(query_id.lower(), {})
        logger.debug(f"CONFIG DEBUG: Specific config for query: {specific_config}")

        # Merge configurations (specific overrides base)
        merged_config = {**base_config, **specific_config}
        logger.debug(f"CONFIG DEBUG: Merged config: {merged_config}")

        metrics = Metrics(
            metric=metric_type,
            alert_threshold=merged_config.get("alert_threshold", 0.1),
            warning_threshold=merged_config.get("warning_threshold", 0.25),
            minor_threshold=merged_config.get("minor_threshold", 0.99),
            major_threshold=merged_config.get("major_threshold", 0.0),
            pause_threshold=merged_config.get("pause_threshold", 0.2),
        )

        logger.debug(f"CONFIG DEBUG: Final Metrics object: {metrics}")
        return metrics

    def _validate_config(self) -> None:
        """Validate configuration structure."""
        logger.debug("CONFIG DEBUG: Validating configuration structure...")
        required_metric_types = ["percentage", "equality", "range"]
        for metric_type in required_metric_types:
            if metric_type not in self.global_defaults:
                logger.warning(f"CONFIG DEBUG: Missing global defaults for metric type: {metric_type}")
            else:
                logger.debug(f"CONFIG DEBUG: Found global defaults for {metric_type}: {self.global_defaults[metric_type]}")

        # Validate query types have required fields
        for query_type, info in self.query_types.items():
            logger.debug(f"CONFIG DEBUG: Validating query type '{query_type}': {info}")
            if "metric" not in info:
                logger.error(f"CONFIG DEBUG: Query type '{query_type}' missing 'metric' field")
            if "handler" not in info:
                logger.error(f"CONFIG DEBUG: Query type '{query_type}' missing 'handler' field")

        logger.debug("CONFIG DEBUG: Configuration validation completed")


async def watch_config(config_watcher: ConfigWatcher, check_interval: float = 5.0) -> None:
    """Watch the config file for changes and reload when modified."""
    while True:
        config_watcher.reload_config()
        await asyncio.sleep(check_interval)
