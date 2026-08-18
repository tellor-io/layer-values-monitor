"""Logger."""

import logging
import os
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv

LOG_RETENTION_HOURS = 24
ENABLE_FILE_LOGS_ENV = "LVM_ENABLE_FILE_LOGS"
JOURNAL_LOG_LEVEL_ENV = "LVM_JOURNAL_LOG_LEVEL"
DEBUG_FILE_LOG_LEVEL_ENV = "LVM_DEBUG_FILE_LOG_LEVEL"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEBUG_LOG_FILE = PROJECT_ROOT / "debug_log.log"
TERMINAL_LOG_FILE = PROJECT_ROOT / "terminal_log.log"

load_dotenv()


def _file_logs_enabled() -> bool:
    """Return whether local rotating text logs should be written."""
    return os.getenv(ENABLE_FILE_LOGS_ENV, "").lower() in ("true", "1", "yes")


def _get_log_level(env_var: str, default: int) -> int:
    """Read a logging level from the environment."""
    configured_level = os.getenv(env_var)
    if not configured_level:
        return default

    normalized_level = configured_level.upper()
    if normalized_level.isdigit():
        return int(normalized_level)

    level = logging.getLevelName(normalized_level)
    if isinstance(level, int):
        return level

    return default


def _reset_handlers(configured_logger: logging.Logger) -> None:
    """Close existing handlers before configuring this module's loggers."""
    for handler in configured_logger.handlers[:]:
        configured_logger.removeHandler(handler)
        handler.close()


debug_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
terminal_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_logs_enabled = _file_logs_enabled()
journal_log_level = _get_log_level(JOURNAL_LOG_LEVEL_ENV, logging.INFO)
debug_file_log_level = _get_log_level(DEBUG_FILE_LOG_LEVEL_ENV, logging.DEBUG)

# Package logger: captures all layer_values_monitor.* records.
package_logger = logging.getLogger("layer_values_monitor")
_reset_handlers(package_logger)
package_logger.setLevel(logging.DEBUG)
package_logger.propagate = False

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(journal_log_level)
stdout_handler.setFormatter(debug_formatter)

package_logger.addHandler(stdout_handler)

if file_logs_enabled:
    debug_file_handler = TimedRotatingFileHandler(
        DEBUG_LOG_FILE,
        when="h",
        interval=1,
        backupCount=LOG_RETENTION_HOURS,
        utc=True,
    )
    debug_file_handler.setLevel(debug_file_log_level)
    debug_file_handler.setFormatter(debug_formatter)
    package_logger.addHandler(debug_file_handler)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a separate console logger for clean terminal output.
console_logger = logging.getLogger("console")
_reset_handlers(console_logger)
console_logger.setLevel(logging.DEBUG)
console_logger.propagate = False

console_only_handler = logging.StreamHandler(sys.stdout)
console_only_handler.setLevel(journal_log_level)
console_only_handler.setFormatter(terminal_formatter)
console_logger.addHandler(console_only_handler)

if file_logs_enabled:
    full_file_handler = TimedRotatingFileHandler(
        TERMINAL_LOG_FILE,
        when="h",
        interval=1,
        backupCount=LOG_RETENTION_HOURS,
        utc=True,
    )
    full_file_handler.setLevel(logging.INFO)
    full_file_handler.setFormatter(terminal_formatter)
    console_logger.addHandler(full_file_handler)
