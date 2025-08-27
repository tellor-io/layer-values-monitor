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


@pytest.fixture
def saga_config_file():
    """Create a temporary config file for Saga testing with contract addresses."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".toml")
    temp_file_path = Path(temp_file.name)

    # Write config with contract addresses
    with open(temp_file_path, "w") as f:
        f.write("""
            [test_query_id]
            metric = "percentage"
            alert_threshold = 0.05
            warning_threshold = 0.1
            minor_threshold = 0.15
            major_threshold = 0.2
            pause_threshold = 0.25
            contract_address = "0x9fe237b245466A5f088AfE808b27c1305E3027BC"
            
            [another_query_id]
            metric = "percentage"
            alert_threshold = 0.1
            warning_threshold = 0.2
            minor_threshold = 0.3
            major_threshold = 0.4
            pause_threshold = 0.5
            contract_address = "0x0000000000000000000000000000000000000000"
        """)

    time.sleep(0.1)
    yield temp_file_path
    os.unlink(temp_file_path)


@pytest.fixture
def saga_config_watcher(saga_config_file):
    """Create a ConfigWatcher instance for Saga testing."""
    return ConfigWatcher(saga_config_file)


@pytest.fixture
def mock_web3():
    """Mock Web3 instance for testing contract interactions."""
    mock_w3 = MagicMock()
    mock_w3.eth = MagicMock()
    mock_w3.eth.block_number = 12345678
    mock_w3.eth.gas_price = 20000000000  # 20 gwei
    mock_w3.is_address.return_value = True
    mock_w3.to_checksum_address.side_effect = lambda x: x.upper()
    mock_w3.eth.get_code.return_value = b"contract_bytecode"
    mock_w3.eth.get_transaction_count.return_value = 5
    return mock_w3


@pytest.fixture
def mock_saga_contract_manager():
    """Mock SagaContractManager for testing."""
    from layer_values_monitor.saga_contract import SagaContractManager

    manager = MagicMock(spec=SagaContractManager)
    manager.pause_contract = AsyncMock(return_value=("0xtest_transaction_hash", "success"))
    manager.is_guardian = AsyncMock(return_value=True)
    manager.is_paused = AsyncMock(return_value=False)
    manager.is_connected.return_value = True
    return manager


@pytest.fixture
def sample_aggregate_report():
    """Create a sample aggregate report for testing."""
    from layer_values_monitor.custom_types import AggregateReport

    return AggregateReport(
        query_id="test_query_id",
        query_data="0x123abc",
        value="0x" + "0" * 63 + "1",  # 1 in hex with padding
        aggregate_power="1000",
        micro_report_height="12345",
        height=12345,
    )
