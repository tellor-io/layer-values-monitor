"""Tests for aggregate report monitoring with Saga contract integration."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.custom_types import AggregateReport
from layer_values_monitor.monitor import agg_reports_queue_handler, inspect_aggregate_report
from layer_values_monitor.saga_contract import SagaContractManager
from layer_values_monitor.threshold_config import ThresholdConfig

import pytest


class TestAggReportsQueueHandler:
    """Test cases for agg_reports_queue_handler with Saga integration."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger for testing."""
        return MagicMock(spec=logging.Logger)

    @pytest.fixture
    def mock_config_watcher(self):
        """Create a mock config watcher."""
        watcher = MagicMock(spec=ConfigWatcher)
        watcher.get_config.return_value = {
            "test_query_id": {
                "metric": "percentage",
                "alert_threshold": 0.05,
                "warning_threshold": 0.1,
                "minor_threshold": 0.15,
                "major_threshold": 0.2,
                "pause_threshold": 0.25,
                "datafeed_ca": "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
            }
        }
        return watcher

    @pytest.fixture
    def mock_threshold_config(self):
        """Create a mock threshold config."""
        return MagicMock(spec=ThresholdConfig)

    @pytest.fixture
    def mock_saga_manager(self):
        """Create a mock Saga contract manager."""
        manager = MagicMock(spec=SagaContractManager)
        manager.pause_contract = AsyncMock(return_value=("0xtest_hash", "success"))
        return manager

    @pytest.fixture
    def sample_aggregate_report(self):
        """Create a sample aggregate report."""
        return AggregateReport(
            query_id="test_query_id",
            query_data="0x123abc",
            value="0x" + "0" * 63 + "1",  # 1 in hex with padding
            aggregate_power="1000",
            micro_report_height="12345",
            height=12345,
        )

    @pytest.mark.asyncio
    async def test_handler_with_pause_trigger(
        self, mock_logger, mock_config_watcher, mock_threshold_config, mock_saga_manager, sample_aggregate_report
    ):
        """Test queue handler when pause threshold is exceeded."""
        queue = asyncio.Queue()
        await queue.put(sample_aggregate_report)

        # Mock inspect_aggregate_report to return should_pause=True
        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = (True, "Test pause reason")

            # Create task and let it process one item
            task = asyncio.create_task(agg_reports_queue_handler(queue, mock_config_watcher, mock_logger, mock_saga_manager))

            # Wait a short time for processing
            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify pause_contract was called
            mock_saga_manager.pause_contract.assert_called_once_with(
                "0x9fe237b245466A5f088AfE808b27c1305E3027BC", "test_query_id"
            )

            # Verify logging
            mock_logger.critical.assert_any_call("🚨 CIRCUIT BREAKER ACTIVATED: Test pause reason")
            mock_logger.critical.assert_any_call("🚨 CONTRACT PAUSED SUCCESSFULLY - TxHash: 0xtest_hash")

    @pytest.mark.asyncio
    async def test_handler_with_pause_failure(
        self, mock_logger, mock_config_watcher, mock_threshold_config, mock_saga_manager, sample_aggregate_report
    ):
        """Test queue handler when pause contract call fails."""
        queue = asyncio.Queue()
        await queue.put(sample_aggregate_report)

        # Mock pause_contract to return None (failure)
        mock_saga_manager.pause_contract = AsyncMock(return_value=(None, "not_guardian"))

        # Mock inspect_aggregate_report to return should_pause=True
        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = (True, "Test pause reason")

            # Create task and let it process one item
            task = asyncio.create_task(agg_reports_queue_handler(queue, mock_config_watcher, mock_logger, mock_saga_manager))

            # Wait a short time for processing
            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify error logging
            mock_logger.error.assert_called_with(
                "❌ NOT AUTHORIZED - Account is not a guardian for contract 0x9fe237b245466A5f088AfE808b27c1305E3027BC"
            )

    @pytest.mark.asyncio
    async def test_handler_with_placeholder_address(
        self, mock_logger, mock_config_watcher, mock_threshold_config, mock_saga_manager, sample_aggregate_report
    ):
        """Test queue handler with placeholder contract address."""
        # Configure placeholder address
        mock_config_watcher.get_config.return_value = {
            "test_query_id": {"datafeed_ca": "0x0000000000000000000000000000000000000000"}
        }

        queue = asyncio.Queue()
        await queue.put(sample_aggregate_report)

        # Mock inspect_aggregate_report to return should_pause=True
        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = (True, "Test pause reason")

            # Create task and let it process one item
            task = asyncio.create_task(agg_reports_queue_handler(queue, mock_config_watcher, mock_logger, mock_saga_manager))

            # Wait a short time for processing
            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify pause_contract was NOT called
            mock_saga_manager.pause_contract.assert_not_called()

            # Verify warning
            mock_logger.warning.assert_called_with(
                "⚠️ PAUSE SKIPPED - No valid contract address configured for query test_query_id..."
            )

    @pytest.mark.asyncio
    async def test_handler_without_saga_manager(
        self, mock_logger, mock_config_watcher, mock_threshold_config, sample_aggregate_report
    ):
        """Test queue handler without Saga contract manager."""
        queue = asyncio.Queue()
        await queue.put(sample_aggregate_report)

        # Mock inspect_aggregate_report to return should_pause=True
        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = (True, "Test pause reason")

            # Create task with None saga_manager
            task = asyncio.create_task(
                agg_reports_queue_handler(
                    queue,
                    mock_config_watcher,
                    mock_logger,
                    None,  # No saga manager
                )
            )

            # Wait a short time for processing
            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify warning about missing manager
            mock_logger.warning.assert_called_with(
                "⚠️ PAUSE SKIPPED - Saga contract manager not initialized (check SAGA_EVM_RPC_URL and SAGA_PRIVATE_KEY)"
            )

    @pytest.mark.asyncio
    async def test_handler_no_pause_needed(
        self, mock_logger, mock_config_watcher, mock_threshold_config, mock_saga_manager, sample_aggregate_report
    ):
        """Test queue handler when no pause is needed."""
        queue = asyncio.Queue()
        await queue.put(sample_aggregate_report)

        # Mock inspect_aggregate_report to return should_pause=False
        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = (False, "Values within threshold")

            # Create task and let it process one item
            task = asyncio.create_task(agg_reports_queue_handler(queue, mock_config_watcher, mock_logger, mock_saga_manager))

            # Wait a short time for processing
            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify pause_contract was NOT called
            mock_saga_manager.pause_contract.assert_not_called()

            # Check that no pause was triggered (no CIRCUIT BREAKER message)
            critical_calls = [call for call in mock_logger.critical.call_args_list if "CIRCUIT BREAKER" in str(call)]
            assert len(critical_calls) == 0, f"Unexpected circuit breaker activation: {critical_calls}"

    @pytest.mark.asyncio
    async def test_handler_inspection_failure(
        self, mock_logger, mock_config_watcher, mock_threshold_config, mock_saga_manager, sample_aggregate_report
    ):
        """Test queue handler when inspection fails."""
        queue = asyncio.Queue()
        await queue.put(sample_aggregate_report)

        # Mock inspect_aggregate_report to return None
        with patch("layer_values_monitor.monitor.inspect_aggregate_report") as mock_inspect:
            mock_inspect.return_value = None

            # Create task and let it process one item
            task = asyncio.create_task(agg_reports_queue_handler(queue, mock_config_watcher, mock_logger, mock_saga_manager))

            # Wait a short time for processing
            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Verify warning about inspection failure
            mock_logger.warning.assert_called_with(
                "Could not validate aggregate report - configuration or trusted source unavailable"
            )


class TestInspectAggregateReport:
    """Test cases for inspect_aggregate_report function."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger for testing."""
        return MagicMock(spec=logging.Logger)

    @pytest.fixture
    def mock_config_watcher(self):
        """Create a mock config watcher."""
        from layer_values_monitor.custom_types import Metrics

        watcher = MagicMock(spec=ConfigWatcher)
        watcher.get_config.return_value = {
            "test_query_id": {
                "metric": "percentage",
                "alert_threshold": 0.05,
                "warning_threshold": 0.1,
                "minor_threshold": 0.15,
                "major_threshold": 0.2,
                "pause_threshold": 0.25,
            }
        }
        watcher.is_supported_query_type.return_value = True
        watcher.get_metrics_for_query.return_value = Metrics(
            metric="percentage",
            alert_threshold=0.05,
            warning_threshold=0.1,
            minor_threshold=0.15,
            major_threshold=0.2,
            pause_threshold=0.25,
        )
        return watcher

    @pytest.fixture
    def mock_threshold_config(self):
        """Create a mock threshold config."""
        return MagicMock(spec=ThresholdConfig)

    @pytest.fixture
    def sample_aggregate_report(self):
        """Create a sample aggregate report."""
        return AggregateReport(
            query_id="test_query_id",
            query_data="0x123abc",
            value="0x" + "0" * 63 + "1",  # 1 in hex with padding
            aggregate_power="1000",
            micro_report_height="12345",
            height=12345,
        )

    @pytest.mark.asyncio
    async def test_inspect_should_pause(
        self, mock_logger, mock_config_watcher, mock_threshold_config, sample_aggregate_report
    ):
        """Test inspection that should trigger pause."""
        with patch("layer_values_monitor.monitor.get_query") as mock_get_query:
            with patch("layer_values_monitor.monitor.get_feed") as mock_get_feed:
                with patch("layer_values_monitor.monitor.fetch_value") as mock_fetch_value:
                    with patch("layer_values_monitor.monitor.decode_hex_value") as mock_decode:
                        with patch("layer_values_monitor.monitor.is_disputable") as mock_is_disputable:
                            # Setup mocks
                            mock_get_query.return_value = MagicMock()
                            mock_get_feed.return_value = MagicMock()
                            mock_fetch_value.return_value = (100.0, None)
                            mock_decode.return_value = 130.0  # 30% difference
                            mock_is_disputable.return_value = (True, True, 0.3)  # 30% diff > 25% pause threshold

                            result = await inspect_aggregate_report(
                                sample_aggregate_report, mock_config_watcher, mock_logger
                            )

                            assert result is not None
                            # inspect_aggregate_report returns (should_pause, reason) without power_thresholds
                            should_pause, reason = result
                            assert should_pause is True
                            assert "exceeds pause threshold" in reason

    @pytest.mark.asyncio
    async def test_inspect_should_not_pause(
        self, mock_logger, mock_config_watcher, mock_threshold_config, sample_aggregate_report
    ):
        """Test inspection that should not trigger pause."""
        with patch("layer_values_monitor.monitor.get_query") as mock_get_query:
            with patch("layer_values_monitor.monitor.get_feed") as mock_get_feed:
                with patch("layer_values_monitor.monitor.fetch_value") as mock_fetch_value:
                    with patch("layer_values_monitor.monitor.decode_hex_value") as mock_decode:
                        with patch("layer_values_monitor.monitor.is_disputable") as mock_is_disputable:
                            # Setup mocks
                            mock_get_query.return_value = MagicMock()
                            mock_get_feed.return_value = MagicMock()
                            mock_fetch_value.return_value = (100.0, None)
                            mock_decode.return_value = 105.0  # 5% difference
                            mock_is_disputable.return_value = (False, False, 0.05)  # 5% diff < 25% pause threshold

                            result = await inspect_aggregate_report(
                                sample_aggregate_report, mock_config_watcher, mock_logger
                            )

                            assert result is not None
                            # inspect_aggregate_report returns (should_pause, reason) without power_thresholds
                            should_pause, reason = result
                            assert should_pause is False
                            assert "acceptable deviation:" in reason

    @pytest.mark.asyncio
    async def test_inspect_no_trusted_value(
        self, mock_logger, mock_config_watcher, mock_threshold_config, sample_aggregate_report
    ):
        """Test inspection when trusted value cannot be fetched."""
        with patch("layer_values_monitor.monitor.get_query") as mock_get_query:
            with patch("layer_values_monitor.monitor.get_feed") as mock_get_feed:
                with patch("layer_values_monitor.monitor.fetch_value") as mock_fetch_value:
                    # Setup mocks
                    mock_get_query.return_value = MagicMock()
                    mock_get_feed.return_value = MagicMock()
                    mock_fetch_value.return_value = (None, None)  # No trusted value

                    result = await inspect_aggregate_report(
                        sample_aggregate_report, mock_config_watcher, mock_logger, mock_threshold_config
                    )

                    assert result is None
                    mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_inspect_no_config(self, mock_logger, mock_config_watcher, mock_threshold_config, sample_aggregate_report):
        """Test inspection with no configuration available."""
        # Mock config watcher to return no metrics
        mock_config_watcher.is_supported_query_type.return_value = False

        with patch("layer_values_monitor.monitor.get_query") as mock_get_query:
            mock_get_query.return_value = MagicMock()
            mock_get_query.return_value.__class__.__name__ = "SpotPrice"

            result = await inspect_aggregate_report(sample_aggregate_report, mock_config_watcher, mock_logger)

            assert result is None
            mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_inspect_invalid_config(
        self, mock_logger, mock_config_watcher, mock_threshold_config, sample_aggregate_report
    ):
        """Test inspection with invalid configuration."""
        # Return config with missing fields
        mock_config_watcher.get_config.return_value = {
            "test_query_id": {
                "metric": "percentage",
                "alert_threshold": None,  # Invalid
                "warning_threshold": 0.1,
            }
        }

        # Mock config watcher to return None metrics (invalid config)
        mock_config_watcher.get_metrics_for_query.return_value = None
        mock_config_watcher.is_supported_query_type.return_value = True

        with patch("layer_values_monitor.monitor.get_query") as mock_get_query:
            mock_get_query.return_value = MagicMock()
            mock_get_query.return_value.__class__.__name__ = "SpotPrice"

            result = await inspect_aggregate_report(sample_aggregate_report, mock_config_watcher, mock_logger)

            assert result is None
            mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_inspect_disputable_major_threshold(
        self, mock_logger, mock_config_watcher, mock_threshold_config, sample_aggregate_report
    ):
        """Test inspection with disputable value exceeding major threshold."""
        with patch("layer_values_monitor.monitor.get_query") as mock_get_query:
            with patch("layer_values_monitor.monitor.get_feed") as mock_get_feed:
                with patch("layer_values_monitor.monitor.fetch_value") as mock_fetch_value:
                    with patch("layer_values_monitor.monitor.decode_hex_value") as mock_decode:
                        with patch("layer_values_monitor.monitor.is_disputable") as mock_is_disputable:
                            with patch("layer_values_monitor.monitor.determine_dispute_category") as mock_category:
                                # Setup mocks
                                mock_get_query.return_value = MagicMock()
                                mock_get_feed.return_value = MagicMock()
                                mock_fetch_value.return_value = (100.0, None)
                                mock_decode.return_value = 120.0  # 20% difference
                                mock_is_disputable.return_value = (True, True, 0.2)  # 20% diff < 25% pause threshold
                                mock_category.return_value = "major"

                                result = await inspect_aggregate_report(
                                    sample_aggregate_report, mock_config_watcher, mock_logger
                                )

                                assert result is not None
                                # inspect_aggregate_report returns (should_pause, reason) without power_thresholds
                                should_pause, reason = result
                                assert should_pause is False
                                assert "major threshold" in reason
