"""Integration tests for Saga contract monitoring functionality."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.custom_types import AggregateReport
from layer_values_monitor.saga_contract import create_saga_contract_manager

import pytest


class TestSagaIntegration:
    """Integration tests for the complete Saga monitoring flow."""

    @pytest.mark.asyncio
    async def test_end_to_end_pause_flow(self, mock_saga_contract_manager, saga_config_watcher):
        """Test the complete flow from aggregate report to contract pause."""
        from layer_values_monitor.monitor import agg_reports_queue_handler

        # Create aggregate report that will trigger pause
        agg_report = AggregateReport(
            query_id="test_query_id",
            query_data="0x123abc",
            value="0x" + "0" * 63 + "1",  # Very low value
            aggregate_power="1000",
            micro_report_height="12345",
            height=12345,
        )

        queue = asyncio.Queue()
        await queue.put(agg_report)

        mock_logger = MagicMock()
        MagicMock()

        # Mock the inspection to return should_pause=True
        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = (True, "Deviation exceeds pause threshold")

            # Run the queue handler for a short time
            task = asyncio.create_task(
                agg_reports_queue_handler(queue, saga_config_watcher, mock_logger, mock_saga_contract_manager)
            )

            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify the complete flow
            mock_saga_contract_manager.pause_contract.assert_called_once_with(
                "0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id"
            )

            # Verify proper logging
            mock_logger.critical.assert_any_call("🚨 CIRCUIT BREAKER ACTIVATED: Deviation exceeds pause threshold")
            mock_logger.critical.assert_any_call("🚨 CONTRACT PAUSED SUCCESSFULLY - TxHash: 0xtest_transaction_hash")

    def test_saga_manager_creation_with_env_vars(self):
        """Test SagaContractManager creation from environment variables."""
        mock_logger = MagicMock()

        with patch.dict(os.environ, {"SAGA_PRIVATE_KEY": "test_private_key"}):
            with patch("layer_values_monitor.saga_contract.get_saga_web3_connection") as mock_get_conn:
                mock_w3 = MagicMock()
                mock_get_conn.return_value = (mock_w3, 123456)

                with patch("layer_values_monitor.saga_contract.SagaContractManager") as mock_manager_class:
                    mock_manager = MagicMock()
                    mock_manager.is_connected.return_value = True
                    mock_manager_class.return_value = mock_manager

                    result = create_saga_contract_manager(mock_logger)

                    assert result is not None
                    mock_manager_class.assert_called_once_with(mock_w3, "test_private_key", mock_logger)

    def test_saga_manager_creation_missing_env_vars(self):
        """Test SagaContractManager creation with missing environment variables."""
        mock_logger = MagicMock()

        # Clear environment variables
        with patch.dict(os.environ, {}, clear=True):
            result = create_saga_contract_manager(mock_logger)

            assert result is None
            mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_multiple_aggregate_reports(self, mock_saga_contract_manager, saga_config_watcher):
        """Test handling multiple aggregate reports with different outcomes."""
        from layer_values_monitor.monitor import agg_reports_queue_handler

        # Create multiple reports
        report1 = AggregateReport(
            query_id="test_query_id",
            query_data="0x123abc",
            value="0x" + "0" * 63 + "1",
            aggregate_power="1000",
            micro_report_height="12345",
            height=12345,
        )

        report2 = AggregateReport(
            query_id="another_query_id",
            query_data="0x456def",
            value="0x" + "0" * 63 + "2",
            aggregate_power="2000",
            micro_report_height="12346",
            height=12346,
        )

        queue = asyncio.Queue()
        await queue.put(report1)
        await queue.put(report2)

        mock_logger = MagicMock()
        MagicMock()

        # Mock different inspection results
        def side_effect(agg_report, *args):
            if agg_report.query_id == "test_query_id":
                return (True, "Should pause")  # First report triggers pause
            else:
                return (False, "Within limits")  # Second report is fine

        with patch("layer_values_monitor.monitor.inspect_aggregate_report", side_effect=side_effect):
            # Run the queue handler
            task = asyncio.create_task(
                agg_reports_queue_handler(queue, saga_config_watcher, mock_logger, mock_saga_contract_manager)
            )

            await asyncio.sleep(0.2)  # Give time to process both reports
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify only one pause attempt (for the first report)
            mock_saga_contract_manager.pause_contract.assert_called_once_with(
                "0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id"
            )

            # Verify pause was executed
            assert any("CONTRACT PAUSED SUCCESSFULLY" in str(call) for call in mock_logger.critical.call_args_list)

    @pytest.mark.asyncio
    async def test_contract_pause_with_guardian_failure(self, saga_config_watcher):
        """Test contract pause when guardian check fails."""
        from layer_values_monitor.monitor import agg_reports_queue_handler

        # Create mock saga manager that fails guardian check
        mock_saga_manager = MagicMock()
        mock_saga_manager.pause_contract = AsyncMock(return_value=(None, "not_guardian"))  # Failure

        report = AggregateReport(
            query_id="test_query_id",
            query_data="0x123abc",
            value="0x" + "0" * 63 + "1",
            aggregate_power="1000",
            micro_report_height="12345",
            height=12345,
        )

        queue = asyncio.Queue()
        await queue.put(report)

        mock_logger = MagicMock()
        MagicMock()

        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = (True, "Should pause")

            task = asyncio.create_task(agg_reports_queue_handler(queue, saga_config_watcher, mock_logger, mock_saga_manager))

            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify error logging when pause fails
            mock_logger.error.assert_called_with(
                "❌ NOT AUTHORIZED - Account is not a guardian for contract 0x9fe237b245466A5f088AfE808b27c1305E3027BC"
            )

    @pytest.mark.asyncio
    async def test_config_reload_during_monitoring(self, saga_config_watcher):
        """Test that config changes are picked up during monitoring."""
        from layer_values_monitor.monitor import agg_reports_queue_handler

        # Initial datafeed_ca
        initial_config = saga_config_watcher.find_query_config("test_query_id")

        # Prepare new config for mocking
        new_config = dict(initial_config)
        new_config["datafeed_ca"] = "0xNEWADDRESS123456789"

        # Mock config watcher to return new config
        with patch.object(saga_config_watcher, "find_query_config", return_value=new_config):
            report = AggregateReport(
                query_id="test_query_id",
                query_data="0x123abc",
                value="0x" + "0" * 63 + "1",
                aggregate_power="1000",
                micro_report_height="12345",
                height=12345,
            )

            queue = asyncio.Queue()
            await queue.put(report)

            mock_logger = MagicMock()
            MagicMock()
            mock_saga_manager = MagicMock()
            mock_saga_manager.pause_contract = AsyncMock(return_value=("0xtest_hash", "success"))

            with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
                mock_inspect.return_value = (True, "Should pause")

                task = asyncio.create_task(
                    agg_reports_queue_handler(queue, saga_config_watcher, mock_logger, mock_saga_manager)
                )

                await asyncio.sleep(0.1)
                task.cancel()

                try:
                    await task
                except asyncio.CancelledError:
                    pass

                # Verify pause was called with the new address
                mock_saga_manager.pause_contract.assert_called_once_with("0xNEWADDRESS123456789", "test_query_id")

    def test_abi_compatibility(self):
        """Test that the ABI matches the GuardedPausable contract."""
        from layer_values_monitor.saga_contract import SagaContractManager

        mock_logger = MagicMock()
        mock_web3 = MagicMock()
        mock_web3.eth.account.from_key.return_value = MagicMock()

        manager = SagaContractManager(mock_web3, "test_key", mock_logger)

        # Verify ABI contains expected functions
        abi_functions = [func["name"] for func in manager.guarded_pausable_abi if func["type"] == "function"]

        assert "pause" in abi_functions
        assert "unpause" in abi_functions
        assert "paused" in abi_functions
        assert "guardians" in abi_functions

        # Verify function signatures match expected format
        pause_func = next(func for func in manager.guarded_pausable_abi if func["name"] == "pause")
        assert pause_func["inputs"] == []
        assert pause_func["stateMutability"] == "nonpayable"

        guardians_func = next(func for func in manager.guarded_pausable_abi if func["name"] == "guardians")
        assert len(guardians_func["inputs"]) == 1
        assert guardians_func["inputs"][0]["type"] == "address"
