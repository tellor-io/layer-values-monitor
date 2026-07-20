"""Module to watch and manage a live configuration."""

from __future__ import annotations

import asyncio
import time
import tomllib
from pathlib import Path

from layer_values_monitor.custom_types import Metrics
from layer_values_monitor.logger import logger

# Default cache settings
DEFAULT_CHECK_INTERVAL = 180  # 3 minutes
DEFAULT_STALENESS_MULTIPLIER = 3  # Alert if cache is 3x older than check_interval
DEFAULT_REFRESH_THRESHOLD = 0.8  # Refresh when entry reaches 80% of TTL
DEFAULT_ACTIVE_WINDOW_MULTIPLIER = 3  # Consider queries active for 3x their TTL
DEFAULT_MAX_CONCURRENT_REFRESHES = 3


class ConfigWatcher:
    """Class to watch and manage a live configuration."""

    def __init__(self, config_path: Path) -> None:
        """Initialize the configuration watcher."""
        self.config_path = config_path
        self.global_defaults: dict[str, dict] = {}
        self.query_types: dict[str, dict] = {}
        self.query_configs: dict[str, dict[str, dict]] = {}
        self.cache_settings: dict[str, float] = {}
        self.last_modified_time = 0
        self.reload_config()

    def reload_config(self) -> bool:
        """Reload config if modified, return True if reloaded."""
        current_mtime = self.config_path.stat().st_mtime
        if current_mtime <= self.last_modified_time:
            return False

        with open(self.config_path, "rb") as f:
            data = tomllib.load(f)

        # Load cache settings
        cache_config = data.get("cache", {})
        self.cache_settings = {
            "check_interval": float(cache_config.get("check_interval", DEFAULT_CHECK_INTERVAL)),
            "staleness_alert_multiplier": float(
                cache_config.get("staleness_alert_multiplier", DEFAULT_STALENESS_MULTIPLIER)
            ),
            "refresh_threshold": float(cache_config.get("refresh_threshold", DEFAULT_REFRESH_THRESHOLD)),
            "active_window_multiplier": float(
                cache_config.get("active_window_multiplier", DEFAULT_ACTIVE_WINDOW_MULTIPLIER)
            ),
            "max_concurrent_refreshes": int(
                cache_config.get("max_concurrent_refreshes", DEFAULT_MAX_CONCURRENT_REFRESHES)
            ),
        }

        # Normalize all keys to lowercase once
        self.global_defaults = {
            metric_type.lower(): thresholds for metric_type, thresholds in data.get("global_defaults", {}).items()
        }

        self.query_types = {qtype.lower(): info for qtype, info in data.get("query_types", {}).items()}

        # Normalize query configs: queries[query_type][query_id] = config
        self.query_configs = {
            qtype.lower(): {qid.lower(): cfg for qid, cfg in queries.items()}
            for qtype, queries in data.get("queries", {}).items()
        }

        self._validate_config()
        self.last_modified_time = current_mtime
        logger.info(f"Configuration reloaded at {time.strftime('%H:%M:%S')}")
        check_iv = self.cache_settings["check_interval"]
        stale_mult = self.cache_settings["staleness_alert_multiplier"]
        refresh_threshold = self.cache_settings["refresh_threshold"]
        active_window = self.cache_settings["active_window_multiplier"]
        max_refreshes = self.cache_settings["max_concurrent_refreshes"]
        logger.info(
            "Cache settings: "
            f"check_interval={check_iv}s, "
            f"staleness_multiplier={stale_mult}, "
            f"refresh_threshold={refresh_threshold}, "
            f"active_window_multiplier={active_window}, "
            f"max_concurrent_refreshes={max_refreshes}"
        )
        return True

    def get_query_type_info(self, query_type: str) -> dict | None:
        """Get query type information (handler, metric, description)."""
        return self.query_types.get(query_type.lower())

    def is_supported_query_type(self, query_type: str) -> bool:
        """Check if query type is supported."""
        return query_type.lower() in self.query_types

    def is_deprecated_query_type(self, query_type: str) -> bool:
        """Check if query type is marked as deprecated in config."""
        query_type_info = self.query_types.get(query_type.lower())
        return bool(query_type_info.get("deprecated")) if query_type_info else False

    def uses_telliot_catalog(self, query_type: str) -> bool:
        """Check if query type uses telliot catalog for trusted values."""
        query_type_info = self.query_types.get(query_type.lower())
        return query_type_info.get("handler") == "telliot_feeds" if query_type_info else False

    def has_query_config(self, query_id: str, query_type: str) -> bool:
        """Check if query has specific configuration."""
        query_type_configs = self.query_configs.get(query_type.lower(), {})
        return query_id.lower() in query_type_configs

    def has_specific_query_configs(self, query_type: str) -> bool:
        """Check if query type has any specific query configurations beyond defaults.

        Returns True if there are query-specific configs, False if only defaults exist.
        Useful for determining if an unconfigured query should trigger a warning.
        """
        query_type_configs = self.query_configs.get(query_type.lower(), {})
        return any(k != "defaults" for k in query_type_configs.keys())

    def get_query_config(self, query_id: str, query_type: str) -> dict:
        """Get query-specific config (e.g., datafeed_ca, custom thresholds)."""
        query_type_configs = self.query_configs.get(query_type.lower(), {})
        return query_type_configs.get(query_id.lower(), {})

    def get_check_interval(self, query_id: str | None = None, query_type: str | None = None) -> float:
        """Get the check interval for a query, with fallback to global default.

        Args:
            query_id: Optional query ID for per-query override
            query_type: Optional query type (required if query_id is provided)

        Returns:
            Check interval in seconds

        """
        # Try per-query override first
        if query_id and query_type:
            query_config = self.get_query_config(query_id, query_type)
            if "check_interval" in query_config:
                return float(query_config["check_interval"])

        # Fall back to global cache setting
        return self.cache_settings.get("check_interval", DEFAULT_CHECK_INTERVAL)

    def get_staleness_threshold(self, query_id: str | None = None, query_type: str | None = None) -> float:
        """Get the staleness threshold (age at which to alert about stale cache).

        Args:
            query_id: Optional query ID for per-query check_interval override
            query_type: Optional query type (required if query_id is provided)

        Returns:
            Staleness threshold in seconds (check_interval * staleness_multiplier)

        """
        check_interval = self.get_check_interval(query_id, query_type)
        multiplier = self.cache_settings.get("staleness_alert_multiplier", DEFAULT_STALENESS_MULTIPLIER)
        return check_interval * multiplier

    def get_refresh_threshold(self) -> float:
        """Get the TTL ratio at which proactive refreshes should start."""
        return self.cache_settings.get("refresh_threshold", DEFAULT_REFRESH_THRESHOLD)

    def get_active_window_multiplier(self) -> float:
        """Get the multiplier used to decide whether a query is still active."""
        return self.cache_settings.get("active_window_multiplier", DEFAULT_ACTIVE_WINDOW_MULTIPLIER)

    def get_active_window(self, query_id: str | None = None, query_type: str | None = None) -> float:
        """Get the activity window for a query."""
        return self.get_check_interval(query_id, query_type) * self.get_active_window_multiplier()

    def get_max_concurrent_refreshes(self) -> int:
        """Get the max number of background refreshes allowed in parallel."""
        return int(self.cache_settings.get("max_concurrent_refreshes", DEFAULT_MAX_CONCURRENT_REFRESHES))

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
