import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

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
