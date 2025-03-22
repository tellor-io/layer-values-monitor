import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.config_watcher import ConfigWatcher

import pytest
from dotenv import load_dotenv


@pytest.fixture
def mock_websocket():
    """Fixture for a mock WebSocket connection."""
    mock_ws = AsyncMock()
    mock_ws.send = AsyncMock()
    mock_ws.recv = AsyncMock()
    return mock_ws


@pytest.fixture
def mock_websockets_connect(mock_websocket):
    mock_connect = MagicMock()
    mock_connect.return_value.__aenter__.return_value = mock_websocket
    patcher = patch("websockets.connect", mock_connect)

    mock = patcher.start()
    yield mock
    patcher.stop()


@pytest.fixture
def event_queue():
    return asyncio.Queue()


@pytest.fixture
def disputes_queue():
    return asyncio.Queue()


@pytest.fixture
def test_report_messages():
    """Fixture that loads test report messages from a JSON file."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "test_messages.json")

    with open(json_path) as f:
        return [json.dumps(msg) for msg in json.load(f)]


@pytest.fixture(scope="session", autouse=True)
def load_env():
    load_dotenv(".env", override=True)


@pytest.fixture
def config_file():
    """Create a temporary config file for testing."""
    # Create a temporary file for testing
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".toml")
    temp_file_path = Path(temp_file.name)

    # Write initial config to the file
    with open(temp_file_path, "w") as f:
        f.write("""
            [Feed]
            test = "initial_value"
            
            [Settings]
            interval = 5
        """)

    # Allow filesystem to register the file
    time.sleep(0.1)

    yield temp_file_path

    # Clean up after test
    os.unlink(temp_file_path)


@pytest.fixture
def config_watcher(config_file):
    """Create a ConfigWatcher instance for testing."""
    return ConfigWatcher(config_file)
