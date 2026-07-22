"""Logger."""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv

LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5
ENABLE_FILE_LOGS_ENV = "LVM_ENABLE_FILE_LOGS"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEBUG_LOG_FILE = PROJECT_ROOT / "debug_log.log"
TERMINAL_LOG_FILE = PROJECT_ROOT / "terminal_log.log"

load_dotenv()


def _file_logs_enabled() -> bool:
    """Return whether local rotating text logs should be written."""
    return os.getenv(ENABLE_FILE_LOGS_ENV, "").lower() in ("true", "1", "yes")


def _cleanup_stale_rotated_logs(log_file: Path) -> None:
    """Remove rotated log backups beyond the configured retention count."""
    log_path = log_file
    parent = log_path.parent if log_path.parent != Path("") else Path(".")
    prefix = f"{log_path.name}."

    for rotated_log in parent.glob(f"{log_path.name}.*"):
        suffix = rotated_log.name.removeprefix(prefix)
        if suffix.isdigit() and int(suffix) > LOG_BACKUP_COUNT:
            rotated_log.unlink(missing_ok=True)


def _reset_handlers(configured_logger: logging.Logger) -> None:
    """Close existing handlers before configuring this module's loggers."""
    for handler in configured_logger.handlers[:]:
        configured_logger.removeHandler(handler)
        handler.close()


debug_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
terminal_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_logs_enabled = _file_logs_enabled()

# Package logger: captures all layer_values_monitor.* records and sends them to stdout.
package_logger = logging.getLogger("layer_values_monitor")
_reset_handlers(package_logger)
package_logger.setLevel(logging.DEBUG)
package_logger.propagate = False

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(debug_formatter)

package_logger.addHandler(stdout_handler)

if file_logs_enabled:
    _cleanup_stale_rotated_logs(DEBUG_LOG_FILE)
    debug_file_handler = RotatingFileHandler(
        DEBUG_LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
    debug_file_handler.setLevel(logging.DEBUG)
    debug_file_handler.setFormatter(debug_formatter)
    package_logger.addHandler(debug_file_handler)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a separate console logger for clean terminal output.
console_logger = logging.getLogger("console")
_reset_handlers(console_logger)
console_logger.setLevel(logging.INFO)
console_logger.propagate = False

console_only_handler = logging.StreamHandler(sys.stdout)
console_only_handler.setLevel(logging.INFO)
console_only_handler.setFormatter(terminal_formatter)
console_logger.addHandler(console_only_handler)

if file_logs_enabled:
    _cleanup_stale_rotated_logs(TERMINAL_LOG_FILE)
    full_file_handler = RotatingFileHandler(
        TERMINAL_LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
    full_file_handler.setLevel(logging.INFO)
    full_file_handler.setFormatter(terminal_formatter)
    console_logger.addHandler(full_file_handler)
