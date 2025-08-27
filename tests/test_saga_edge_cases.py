"""Edge case and performance tests for Saga contract monitoring."""

import asyncio
import logging
from unittest.mock import MagicMock, PropertyMock, patch

from layer_values_monitor.custom_types import AggregateReport
from layer_values_monitor.saga_contract import SagaContractManager

import pytest
from web3.exceptions import TransactionNotFound, Web3Exception


class TestSagaEdgeCases:
    """Test edge cases and error conditions for Saga monitoring."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger for testing."""
        return MagicMock(spec=logging.Logger)

    @pytest.fixture
    def saga_manager(self, mock_logger):
        """Create a SagaContractManager instance with mocked dependencies."""
        with patch("layer_values_monitor.saga_contract.Web3") as mock_web3_class:
            mock_web3 = MagicMock()
            mock_web3.eth.block_number = 12345678
            mock_web3.eth.gas_price = 20000000000
            mock_web3.is_address.return_value = True
            mock_web3.to_checksum_address.side_effect = lambda x: x.upper()
            mock_web3.eth.get_code.return_value = b"contract_code"
            mock_web3.eth.get_transaction_count.return_value = 5
            mock_web3_class.return_value = mock_web3

            with patch("layer_values_monitor.saga_contract.Web3.eth.account.from_key") as mock_from_key:
                mock_account = MagicMock()
                mock_account.address = "0x742d35Cc6634C0532925a3b8D404d8E3c3dd542B"
                mock_account.key = b"test_private_key"
                mock_from_key.return_value = mock_account

                manager = SagaContractManager("https://chainlet-2742.saga.xyz/", "test_private_key", mock_logger)
                manager.w3 = mock_web3
                manager.account = mock_account
                return manager

    @pytest.mark.asyncio
    async def test_pause_contract_network_error(self, saga_manager, mock_logger):
        """Test pause contract with network connectivity issues."""
        # Mock network error during transaction sending
        saga_manager.w3.eth.send_raw_transaction.side_effect = Web3Exception("Network error")

        # Mock successful pre-checks
        with patch.object(saga_manager, "is_guardian", return_value=True):
            with patch.object(saga_manager, "is_paused", return_value=False):
                result = await saga_manager.pause_contract("0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id")

                assert result is None
                mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_pause_contract_out_of_gas(self, saga_manager, mock_logger):
        """Test pause contract with out of gas error."""
        # Mock successful pre-checks
        with patch.object(saga_manager, "is_guardian", return_value=True):
            with patch.object(saga_manager, "is_paused", return_value=False):
                # Mock transaction building
                mock_contract = MagicMock()
                saga_manager.w3.eth.contract.return_value = mock_contract
                mock_contract.functions.pause.return_value.build_transaction.side_effect = Web3Exception(
                    "Gas required exceeds allowance"
                )

                result = await saga_manager.pause_contract("0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id")

                assert result is None
                mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_pause_contract_invalid_nonce(self, saga_manager, mock_logger):
        """Test pause contract with nonce issues."""
        # Mock nonce error
        saga_manager.w3.eth.get_transaction_count.side_effect = Web3Exception("Invalid nonce")

        with patch.object(saga_manager, "is_guardian", return_value=True):
            with patch.object(saga_manager, "is_paused", return_value=False):
                result = await saga_manager.pause_contract("0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id")

                assert result is None
                mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_pause_contract_receipt_not_found(self, saga_manager, mock_logger):
        """Test pause contract when transaction receipt is not found."""
        with patch.object(saga_manager, "is_guardian", return_value=True):
            with patch.object(saga_manager, "is_paused", return_value=False):
                # Mock successful transaction sending
                mock_contract = MagicMock()
                saga_manager.w3.eth.contract.return_value = mock_contract

                mock_transaction = {"from": saga_manager.account.address, "nonce": 5, "gas": 100000, "gasPrice": 20000000000}
                mock_contract.functions.pause.return_value.build_transaction.return_value = mock_transaction

                mock_signed_txn = MagicMock()
                mock_signed_txn.rawTransaction = b"signed_data"

                with patch.object(saga_manager.w3.eth.account, "sign_transaction", return_value=mock_signed_txn):
                    saga_manager.w3.eth.send_raw_transaction.return_value.hex.return_value = "0xtest_hash"

                    # Mock receipt not found
                    saga_manager.w3.eth.wait_for_transaction_receipt.side_effect = TransactionNotFound("Receipt not found")

                    result = await saga_manager.pause_contract("0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id")

                    assert result is None
                    mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_multiple_concurrent_pause_attempts(self, saga_manager, mock_logger):
        """Test handling multiple concurrent pause attempts for the same contract."""
        with patch.object(saga_manager, "is_guardian", return_value=True):
            with patch.object(saga_manager, "is_paused", return_value=False):
                # Mock successful transaction
                mock_contract = MagicMock()
                saga_manager.w3.eth.contract.return_value = mock_contract

                mock_transaction = {"from": saga_manager.account.address, "nonce": 5, "gas": 100000, "gasPrice": 20000000000}
                mock_contract.functions.pause.return_value.build_transaction.return_value = mock_transaction

                mock_signed_txn = MagicMock()
                mock_signed_txn.rawTransaction = b"signed_data"

                with patch.object(saga_manager.w3.eth.account, "sign_transaction", return_value=mock_signed_txn):
                    saga_manager.w3.eth.send_raw_transaction.return_value.hex.return_value = "0xtest_hash"

                    mock_receipt = MagicMock()
                    mock_receipt.status = 1
                    saga_manager.w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

                    # Start multiple pause attempts concurrently
                    tasks = [
                        asyncio.create_task(
                            saga_manager.pause_contract("0x9fe237b245466A5f088AfE808b27c1305E3027BC", f"query_{i}")
                        )
                        for i in range(3)
                    ]

                    results = await asyncio.gather(*tasks)

                    # All should succeed (in this mock scenario)
                    assert all(result == "0xtest_hash" for result in results)

    @pytest.mark.asyncio
    async def test_pause_contract_malformed_address(self, saga_manager, mock_logger):
        """Test pause contract with various malformed addresses."""
        test_addresses = [
            "",  # Empty
            "0x",  # Just prefix
            "not_an_address",  # Invalid format
            "0x123",  # Too short
            "0x" + "z" * 40,  # Invalid hex characters
        ]

        for address in test_addresses:
            saga_manager.w3.is_address.return_value = False

            result = await saga_manager.pause_contract(address, "test_query")

            assert result is None
            mock_logger.error.assert_called_with(f"Invalid contract address format: {address}")
            mock_logger.reset_mock()

    @pytest.mark.asyncio
    async def test_is_guardian_contract_not_found(self, saga_manager, mock_logger):
        """Test is_guardian when contract doesn't exist."""
        saga_manager.w3.eth.contract.side_effect = Web3Exception("Contract not found")

        result = await saga_manager.is_guardian(
            "0x9fe237b245466A5f088AfE808b27c1305E3027BC", "0x742d35Cc6634C0532925a3b8D404d8E3c3dd542B"
        )

        assert result is False
        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_is_paused_rpc_error(self, saga_manager, mock_logger):
        """Test is_paused with RPC errors."""
        mock_contract = MagicMock()
        saga_manager.w3.eth.contract.return_value = mock_contract
        mock_contract.functions.paused.return_value.call.side_effect = Web3Exception("RPC error")

        result = await saga_manager.is_paused("0x9fe237b245466A5f088AfE808b27c1305E3027BC")

        assert result is False
        mock_logger.error.assert_called()

    def test_connection_check_various_errors(self, saga_manager, mock_logger):
        """Test connection check with various error types."""
        error_types = [
            ConnectionError("Connection refused"),
            TimeoutError("Request timeout"),
            Web3Exception("Provider error"),
            Exception("Unknown error"),
        ]

        for error in error_types:
            type(saga_manager.w3.eth).block_number = PropertyMock(side_effect=error)

            result = saga_manager.is_connected()

            assert result is False
            mock_logger.error.assert_called()
            mock_logger.reset_mock()

    @pytest.mark.asyncio
    async def test_high_gas_price_handling(self, saga_manager, mock_logger):
        """Test handling of extremely high gas prices."""
        # Mock very high gas price
        saga_manager.w3.eth.gas_price = 1000000000000  # 1000 gwei

        with patch.object(saga_manager, "is_guardian", return_value=True):
            with patch.object(saga_manager, "is_paused", return_value=False):
                mock_contract = MagicMock()
                saga_manager.w3.eth.contract.return_value = mock_contract

                mock_transaction = {
                    "from": saga_manager.account.address,
                    "nonce": 5,
                    "gas": 100000,
                    "gasPrice": 1000000000000,  # Very high gas price
                }
                mock_contract.functions.pause.return_value.build_transaction.return_value = mock_transaction

                mock_signed_txn = MagicMock()
                mock_signed_txn.rawTransaction = b"signed_data"

                with patch.object(saga_manager.w3.eth.account, "sign_transaction", return_value=mock_signed_txn):
                    saga_manager.w3.eth.send_raw_transaction.return_value.hex.return_value = "0xtest_hash"

                    mock_receipt = MagicMock()
                    mock_receipt.status = 1
                    saga_manager.w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

                    result = await saga_manager.pause_contract("0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id")

                    # Should still succeed despite high gas price
                    assert result == "0xtest_hash"

    @pytest.mark.asyncio
    async def test_aggregate_report_edge_values(self):
        """Test aggregate reports with edge case values."""
        from layer_values_monitor.monitor import decode_hex_value

        edge_cases = [
            ("0x0", 0.0),  # Zero value
            ("0x" + "f" * 64, float(int("f" * 64, 16)) / (10**18)),  # Maximum value
            ("0x1", 1e-18),  # Minimum non-zero value
        ]

        for hex_value, expected in edge_cases:
            result = decode_hex_value(hex_value)
            assert abs(result - expected) < 1e-10  # Allow for floating point precision

    @pytest.mark.asyncio
    async def test_rapid_fire_aggregate_reports(self, mock_saga_contract_manager, saga_config_watcher):
        """Test handling rapid succession of aggregate reports."""
        from layer_values_monitor.monitor import agg_reports_queue_handler
        from layer_values_monitor.threshold_config import ThresholdConfig

        # Create many reports quickly
        reports = [
            AggregateReport(
                query_id="test_query_id",
                query_data="0x123abc",
                value=f"0x{i:064x}",  # Different values
                aggregate_power="1000",
                micro_report_height=str(12345 + i),
                height=12345 + i,
            )
            for i in range(10)
        ]

        queue = asyncio.Queue()
        for report in reports:
            await queue.put(report)

        mock_logger = MagicMock()
        mock_threshold_config = MagicMock(spec=ThresholdConfig)

        # Mock inspection to trigger pause for half the reports
        def side_effect(agg_report, *args):
            report_num = int(agg_report.value, 16)
            return (report_num % 2 == 0, f"Report {report_num}")

        with patch("layer_values_monitor.monitor.inspect_aggregate_report", side_effect=side_effect):
            task = asyncio.create_task(
                agg_reports_queue_handler(
                    queue, saga_config_watcher, mock_logger, mock_threshold_config, mock_saga_contract_manager
                )
            )

            await asyncio.sleep(0.5)  # Let it process all reports
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should have attempted pause for even-numbered reports (5 attempts)
            assert mock_saga_contract_manager.pause_contract.call_count == 5

    @pytest.mark.asyncio
    async def test_memory_usage_with_large_reports(self):
        """Test memory handling with large aggregate reports."""
        # Create report with large data
        large_data = "0x" + "a" * 10000  # Very large hex string

        report = AggregateReport(
            query_id="test_query_id",
            query_data=large_data,
            value="0x" + "1" * 64,
            aggregate_power="1000",
            micro_report_height="12345",
            height=12345,
        )

        # Verify the report can be created and accessed without issues
        assert len(report.query_data) == 10002  # 0x + 10000 chars
        assert report.query_id == "test_query_id"
        assert report.height == 12345
