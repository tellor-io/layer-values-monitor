import json
from unittest import mock

from layer_values_monitor.dispute import (
    determine_dispute_category,
    determine_dispute_fee,
    propose_msg,
)


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


@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_successful_execution(mock_subprocess_run):
    # Mock successful execution
    mock_process = mock.MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = json.dumps({"code": 0, "txhash": "ABC123"}).encode()
    mock_subprocess_run.return_value = mock_process

    result = propose_msg(
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

    # Assert subprocess.run was called with the correct arguments
    mock_subprocess_run.assert_called_once()
    args, _ = mock_subprocess_run.call_args
    cmd = args[0]

    assert cmd[0] == "layerd"
    assert "tx" in cmd
    assert "dispute" in cmd
    assert "propose-dispute" in cmd
    assert "reporter_address" in cmd
    assert "meta_id" in cmd
    assert "query_id" in cmd
    assert "warning" in cmd
    assert "1000000loya" in cmd
    assert "True" in cmd


@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_cli_error(mock_subprocess_run):
    # Mock execution with non-zero return code
    mock_process = mock.MagicMock()
    mock_process.returncode = 1
    mock_process.stderr = b"Error message"
    mock_subprocess_run.return_value = mock_process

    result = propose_msg(
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


@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_transaction_code_error(mock_subprocess_run):
    # Mock execution with zero return code but non-zero tx code
    mock_process = mock.MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = json.dumps({"code": 1, "raw_log": "Error in transaction"}).encode()
    mock_subprocess_run.return_value = mock_process

    result = propose_msg(
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


@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_exception_handling(mock_subprocess_run):
    # Mock execution with exception
    mock_subprocess_run.side_effect = Exception("Test exception")

    result = propose_msg(
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


@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_logs_success(mock_subprocess_run, mock_logger):
    # Test that successful execution is logged properly
    mock_process = mock.MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = json.dumps({"code": 0, "txhash": "ABC123"}).encode()
    mock_subprocess_run.return_value = mock_process

    propose_msg(
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


@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_logs_cli_error(mock_subprocess_run, mock_logger):
    # Test that CLI errors are logged properly
    mock_process = mock.MagicMock()
    mock_process.returncode = 1
    mock_process.stderr = b"Error message"
    mock_subprocess_run.return_value = mock_process

    propose_msg(
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


@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_logs_transaction_error(mock_subprocess_run, mock_logger):
    # Test that transaction errors are logged properly
    mock_process = mock.MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = json.dumps({"code": 1, "raw_log": "Error in transaction"}).encode()
    mock_subprocess_run.return_value = mock_process

    propose_msg(
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


@mock.patch("layer_values_monitor.dispute.logger")
@mock.patch("layer_values_monitor.dispute.subprocess.run")
def test_logs_exception(mock_subprocess_run, mock_logger):
    # Test that exceptions are logged properly
    mock_subprocess_run.side_effect = Exception("Test exception")

    propose_msg(
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
