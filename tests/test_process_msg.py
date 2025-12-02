import json
from unittest import mock

from layer_values_monitor.dispute import (
    determine_dispute_category,
    determine_dispute_fee,
    propose_msg,
)

import pytest


def test_returns_correct_category_based_on_thresholds():
    category_thresholds = {
        "major": 0.5,
        "minor": 0.2,
        "warning": 0.1,
    }

    # Test when diff meets threshold for major
    assert determine_dispute_category(0.6, category_thresholds) == "major"

    # Test when diff meets threshold for minor but not major
    assert determine_dispute_category(0.3, category_thresholds) == "minor"

    # Test when diff meets threshold for warning but not minor
    assert determine_dispute_category(0.15, category_thresholds) == "warning"

    # Test when diff doesn't meet any threshold
    assert determine_dispute_category(0.05, category_thresholds) is None


def test_returns_none_when_all_thresholds_are_zero():
    zero_thresholds = {
        "major": 0,
        "minor": 0,
        "warning": 0,
    }
    assert determine_dispute_category(0.1, zero_thresholds) is None


def test_calculates_correct_fee_for_each_category():
    # Test fee calculation for warning category (1%)
    assert determine_dispute_fee("warning", 1000) == 10_000_000  # 1% of 1000 * 1,000,000

    # Test fee calculation for minor category (5%)
    assert determine_dispute_fee("minor", 1000) == 50_000_000  # 5% of 1000 * 1,000,000

    # Test fee calculation for major category (100%)
    assert determine_dispute_fee("major", 1000) == 1_000_000_000  # 100% of 1000 * 1,000,000


def test_returns_zero_when_reporter_power_is_zero():
    assert determine_dispute_fee("warning", 0) == 0
    assert determine_dispute_fee("minor", 0) == 0
    assert determine_dispute_fee("major", 0) == 0


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_successful_execution(mock_create_subprocess):
    # Mock successful execution
    mock_process = mock.AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = mock.AsyncMock(return_value=(json.dumps({"code": 0, "txhash": "ABC123"}).encode(), b""))
    mock_create_subprocess.return_value = mock_process

    result = await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    # Assert the result is the txhash
    assert result == "ABC123"

    # Assert create_subprocess_exec was called
    mock_create_subprocess.assert_called_once()
    args, _ = mock_create_subprocess.call_args

    assert args[0] == "layerd"
    assert "tx" in args
    assert "dispute" in args
    assert "propose-dispute" in args
    assert "reporter_address" in args
    assert "meta_id" in args
    assert "query_id" in args
    assert "warning" in args
    assert "1000000loya" in args
    assert "True" in args


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_cli_error(mock_create_subprocess):
    # Mock execution with non-zero return code
    mock_process = mock.AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate = mock.AsyncMock(return_value=(b"", b"Error message"))
    mock_create_subprocess.return_value = mock_process

    result = await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    assert result is None


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_transaction_code_error(mock_create_subprocess):
    # Mock execution with zero return code but non-zero tx code
    mock_process = mock.AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = mock.AsyncMock(
        return_value=(json.dumps({"code": 1, "raw_log": "Error in transaction"}).encode(), b"")
    )
    mock_create_subprocess.return_value = mock_process

    result = await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    assert result is None


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_exception_handling(mock_create_subprocess):
    # Mock execution with exception
    mock_create_subprocess.side_effect = Exception("Test exception")

    result = await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    assert result is None


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_logs_success(mock_create_subprocess, mock_logger):
    # Test that successful execution is logged properly
    mock_process = mock.AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = mock.AsyncMock(return_value=(json.dumps({"code": 0, "txhash": "ABC123"}).encode(), b""))
    mock_create_subprocess.return_value = mock_process

    await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    mock_logger.info.assert_called_once_with("dispute msg executed successfully: ABC123")


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_logs_cli_error(mock_create_subprocess, mock_logger):
    # Test that CLI errors are logged properly
    mock_process = mock.AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate = mock.AsyncMock(return_value=(b"", b"Error message"))
    mock_create_subprocess.return_value = mock_process

    await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    mock_logger.error.assert_called_once()
    # Check that error contains stderr output
    assert "Error message" in str(mock_logger.error.call_args)


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_logs_transaction_error(mock_create_subprocess, mock_logger):
    # Test that transaction errors are logged properly
    mock_process = mock.AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = mock.AsyncMock(
        return_value=(json.dumps({"code": 1, "raw_log": "Error in transaction"}).encode(), b"")
    )
    mock_create_subprocess.return_value = mock_process

    await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    mock_logger.error.assert_called_once_with("failed to execute dispute msg: Error in transaction")


@pytest.mark.asyncio
@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.asyncio.create_subprocess_exec")
async def test_logs_exception(mock_create_subprocess, mock_logger):
    # Test that exceptions are logged properly
    mock_create_subprocess.side_effect = Exception("Test exception")

    await propose_msg(
        binary_path="layerd",
        reporter="reporter_address",
        query_id="query_id",
        meta_id="meta_id",
        dispute_category="warning",
        fee="1000000loya",
        key_name="key_name",
        chain_id="chain_id",
        rpc="http://localhost:26657",
        kb="test",
        kdir="/path/to/keyring",
        payfrom_bond="True",
    )

    mock_logger.error.assert_called_once_with("failed to execute dispute msg: Test exception")
