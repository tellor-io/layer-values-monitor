"""Constants for the Layer Values Monitor."""

from collections import deque
import os
from datetime import datetime, timezone

DENOM = "loya"

TABLE = deque(maxlen=60)
CSV_FILE_PATTERN = "table_{timestamp}.csv"
CURRENT_CSV_FILE = f"table_{int(datetime.now(timezone.utc).timestamp())}.csv"
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs")
