"""Logger."""

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# File handler for logging to file
file_handler = logging.FileHandler("monitor_log.log")
file_handler.setLevel(logging.DEBUG)

# Console handler for logging to terminal
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Only show INFO and above in terminal

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)
