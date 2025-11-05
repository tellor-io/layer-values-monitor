"""Logger."""

import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Debug file handler - captures everything
debug_file_handler = RotatingFileHandler(
    "debug_log.log",
    maxBytes=50 * 1024 * 1024,  # 50MB
    backupCount=20,
)
debug_file_handler.setLevel(logging.DEBUG)

# Full file handler - captures INFO and above (what would go to terminal)
full_file_handler = RotatingFileHandler(
    "terminal_log.log",
    maxBytes=50 * 1024 * 1024,  # 50MB
    backupCount=20,
)
full_file_handler.setLevel(logging.INFO)

# Console handler - only shows CRITICAL by default (we'll use custom console logs)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.CRITICAL)

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
debug_file_handler.setFormatter(formatter)
full_file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(debug_file_handler)
logger.addHandler(full_file_handler)
logger.addHandler(console_handler)

# Create a separate console-only logger for clean terminal output
console_logger = logging.getLogger("console")
console_logger.setLevel(logging.INFO)
console_logger.propagate = False  # Don't propagate to root logger

console_only_handler = logging.StreamHandler()
console_only_handler.setLevel(logging.INFO)
# Format: timestamp - level - message (no module name)
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_only_handler.setFormatter(console_formatter)
console_logger.addHandler(console_only_handler)
