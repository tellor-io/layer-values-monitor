"""Constants for the Layer Values Monitor."""

import os
from collections import deque
from datetime import UTC, datetime

DENOM = "loya"

TABLE = deque(maxlen=60)
CSV_FILE_PATTERN = "table_{timestamp}.csv"
CURRENT_CSV_FILE = f"table_{int(datetime.now(UTC).timestamp())}.csv"
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs")
