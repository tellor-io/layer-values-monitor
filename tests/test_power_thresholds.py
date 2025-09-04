"""Tests for power threshold functionality in Saga pausing logic."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.config_watcher import ConfigWatcher
from layer_values_monitor.custom_types import AggregateReport, PowerThresholds, ReporterQueryResponse, Reporter
from layer_values_monitor.monitor import (
    agg_reports_queue_handler,
    calculate_power_percentage,
    inspect_aggregate_report,
    parse_reporters_response,
    query_reporters,
)
from layer_values_monitor.saga_contract import SagaContractManager
from layer_values_monitor.threshold_config import ThresholdConfig

import pytest


class TestPowerThresholds:
    """Test cases for power threshold functionality."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger for testing."""
        return MagicMock(spec=logging.Logger)

    @pytest.fixture
    def sample_reporters_response(self):
        """Create sample reporters response data."""
        return {
            "reporters": [
                {
                    "address": "tellor1qxvylucflempdl2cv5h5qmudcmqcmu3kw75ykt",
                    "power": "50",
                    "metadata": {
                        "jailed": False,
                        "moniker": "reporter1"
                    }
                },
                {
                    "address": "tellor1qma4ngrq2vqz6j82u548lder3ue6m25agqv9rt", 
                    "power": "30",
                    "metadata": {
                        "jailed": False,
                        "moniker": "reporter2"
                    }
                },
                {
                    "address": "tellor1q7pamj7v8d3wue5t5pwgejktajrnhuzzthwfel",
                    "power": "20",
                    "metadata": {
                        "jailed": True,
                        "moniker": "jailed_reporter"
                    }
                }
            ]
        }

    @pytest.fixture
    def power_thresholds(self):
        """Create power thresholds for testing."""
        return PowerThresholds(
            immediate_pause_threshold=0.66,
            delayed_pause_threshold=0.33
        )

    @pytest.fixture
    def aggregate_report(self):
        """Create a sample aggregate report."""
        return AggregateReport(
            query_id="test_query_id",
            query_data="test_data",
            value="0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
            aggregate_power="60",  # 60 power
            micro_report_height="100"
        )

    def test_parse_reporters_response(self, sample_reporters_response, mock_logger):
        """Test parsing reporters response and calculating total non-jailed power."""
        result = parse_reporters_response(sample_reporters_response, mock_logger)
        
        assert result is not None
        assert len(result.reporters) == 3
        assert result.total_non_jailed_power == 80  # 50 + 30 (jailed reporter excluded)
        
        # Check individual reporters
        reporters = result.reporters
        assert reporters[0].address == "tellor1qxvylucflempdl2cv5h5qmudcmqcmu3kw75ykt"
        assert reporters[0].power == 50
        assert not reporters[0].jailed
        
        assert reporters[2].power == 20
        assert reporters[2].jailed

    @pytest.mark.asyncio
    async def test_calculate_power_percentage_immediate_pause(
        self, aggregate_report, power_thresholds, mock_logger, sample_reporters_response
    ):
        """Test power percentage calculation for immediate pause scenario."""
        # Mock query_reporters to return our sample data
        with patch('layer_values_monitor.monitor.query_reporters') as mock_query:
            mock_query.return_value = ReporterQueryResponse(
                reporters=[
                    Reporter("addr1", 50, False, "rep1"),
                    Reporter("addr2", 30, False, "rep2"),
                    Reporter("addr3", 20, True, "jailed")
                ],
                total_non_jailed_power=80
            )
            
            # Test with aggregate power of 60 out of 80 total = 75%
            result = await calculate_power_percentage(aggregate_report, "localhost:26657", power_thresholds, mock_logger)
            
            assert result is not None
            assert result["aggregate_power"] == 60
            assert result["total_power"] == 80
            assert result["power_percentage"] == 75.0
            assert result["should_pause_immediately"] is True  # 75% > 66%
            assert result["should_pause_delayed"] is True

    @pytest.mark.asyncio
    async def test_calculate_power_percentage_delayed_pause(
        self, power_thresholds, mock_logger
    ):
        """Test power percentage calculation for delayed pause scenario."""
        # Create aggregate report with lower power
        agg_report = AggregateReport(
            query_id="test_query_id",
            query_data="test_data", 
            value="0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
            aggregate_power="40",  # 40 power
            micro_report_height="100"
        )
        
        with patch('layer_values_monitor.monitor.query_reporters') as mock_query:
            mock_query.return_value = ReporterQueryResponse(
                reporters=[
                    Reporter("addr1", 50, False, "rep1"),
                    Reporter("addr2", 30, False, "rep2"),
                    Reporter("addr3", 20, True, "jailed")
                ],
                total_non_jailed_power=80
            )
            
            # Test with aggregate power of 40 out of 80 total = 50%
            result = await calculate_power_percentage(agg_report, "localhost:26657", power_thresholds, mock_logger)
            
            assert result is not None
            assert result["power_percentage"] == 50.0
            assert result["should_pause_immediately"] is False  # 50% < 66%
            assert result["should_pause_delayed"] is True      # 50% > 33%

    @pytest.mark.asyncio
    async def test_calculate_power_percentage_no_pause(
        self, power_thresholds, mock_logger
    ):
        """Test power percentage calculation for no pause scenario."""
        # Create aggregate report with very low power
        agg_report = AggregateReport(
            query_id="test_query_id",
            query_data="test_data",
            value="0x0000000000000000000000000000000000000000000000000de0b6b3a7640000", 
            aggregate_power="20",  # 20 power
            micro_report_height="100"
        )
        
        with patch('layer_values_monitor.monitor.query_reporters') as mock_query:
            mock_query.return_value = ReporterQueryResponse(
                reporters=[
                    Reporter("addr1", 50, False, "rep1"),
                    Reporter("addr2", 30, False, "rep2"),
                    Reporter("addr3", 20, True, "jailed")
                ],
                total_non_jailed_power=80
            )
            
            # Test with aggregate power of 20 out of 80 total = 25%
            result = await calculate_power_percentage(agg_report, "localhost:26657", power_thresholds, mock_logger)
            
            assert result is not None
            assert result["power_percentage"] == 25.0
            assert result["should_pause_immediately"] is False  # 25% < 66%
            assert result["should_pause_delayed"] is False     # 25% < 33%

    @pytest.mark.asyncio
    async def test_query_reporters_failure(self, mock_logger):
        """Test query_reporters handling failure cases."""
        # Mock the function to raise an exception instead of dealing with complex async mocking
        with patch('layer_values_monitor.monitor.query_reporters_rest') as mock_rest:
            with patch('aiohttp.ClientSession') as mock_session:
                # Make the RPC call fail by raising an exception
                mock_session.side_effect = Exception("Connection failed")
                mock_rest.return_value = None  # REST fallback also fails
                
                result = await query_reporters("localhost:26657", mock_logger)
                assert result is None

    @pytest.mark.asyncio
    async def test_inspect_aggregate_report_with_power_thresholds(
        self, aggregate_report, power_thresholds, mock_logger
    ):
        """Test inspect_aggregate_report with power threshold logic."""
        mock_config_watcher = MagicMock(spec=ConfigWatcher)
        mock_config_watcher.get_config.return_value = {
            "test_query_id": {
                "metric": "percentage",
                "alert_threshold": 0.05,
                "warning_threshold": 0.1,
                "minor_threshold": 0.15,
                "major_threshold": 0.2,
                "pause_threshold": 0.25,
            }
        }
        
        mock_threshold_config = MagicMock(spec=ThresholdConfig)
        
        with patch('layer_values_monitor.monitor.get_query') as mock_get_query, \
             patch('layer_values_monitor.monitor.get_feed') as mock_get_feed, \
             patch('layer_values_monitor.monitor.fetch_value') as mock_fetch_value, \
             patch('layer_values_monitor.monitor.calculate_power_percentage') as mock_calc_power:
            
            # Mock the feed chain
            mock_get_query.return_value = MagicMock()
            mock_get_feed.return_value = MagicMock()
            mock_fetch_value.return_value = (1.0, None)  # trusted_value, _
            
            # Mock power calculation for immediate pause scenario
            mock_calc_power.return_value = {
                "aggregate_power": 60,
                "total_power": 80,
                "power_percentage": 75.0,
                "should_pause_immediately": True,
                "should_pause_delayed": True,
                "delay_hours": 12,
                "immediate_threshold": 66.0,
                "delayed_threshold": 33.0,
            }
            
            # Test with significant deviation to trigger pause threshold
            agg_report_bad = AggregateReport(
                query_id="test_query_id",
                query_data="test_data",
                value="0x0000000000000000000000000000000000000000000000001bc16d674ec80000",  # Large value
                aggregate_power="60",
                micro_report_height="100"
            )
            
            result = await inspect_aggregate_report(
                agg_report_bad,
                mock_config_watcher,
                mock_logger,
                mock_threshold_config,
                "localhost:26657",
                power_thresholds
            )
            
            assert result is not None
            should_pause, reason, power_info = result
            assert should_pause is True
            assert "Power: 75.0%" in reason
            assert "PAUSE IMMEDIATELY" in reason
            assert power_info is not None

    @pytest.mark.asyncio
    async def test_power_thresholds_override_traditional_pause(
        self, aggregate_report, power_thresholds, mock_logger
    ):
        """Test that power thresholds override traditional pause logic when enabled."""
        mock_config_watcher = MagicMock(spec=ConfigWatcher)
        mock_config_watcher.get_config.return_value = {
            "test_query_id": {
                "metric": "percentage",
                "alert_threshold": 0.05,
                "warning_threshold": 0.1,
                "minor_threshold": 0.15,
                "major_threshold": 0.2,
                "pause_threshold": 0.25,  # This would normally trigger pause
            }
        }
        
        mock_threshold_config = MagicMock(spec=ThresholdConfig)
        
        with patch('layer_values_monitor.monitor.get_query') as mock_get_query, \
             patch('layer_values_monitor.monitor.get_feed') as mock_get_feed, \
             patch('layer_values_monitor.monitor.fetch_value') as mock_fetch_value, \
             patch('layer_values_monitor.monitor.calculate_power_percentage') as mock_calc_power:
            
            # Mock the feed chain
            mock_get_query.return_value = MagicMock()
            mock_get_feed.return_value = MagicMock()
            mock_fetch_value.return_value = (1.0, None)  # trusted_value, _
            
            # Mock power calculation for low power (should NOT pause despite exceeding pause_threshold)
            mock_calc_power.return_value = {
                "aggregate_power": 20,
                "total_power": 80,
                "power_percentage": 25.0,  # 25% < 33% threshold
                "should_pause_immediately": False,
                "should_pause_delayed": False,
                "delay_hours": 12,
                "immediate_threshold": 66.0,
                "delayed_threshold": 33.0,
            }
            
            # Test with significant deviation that would normally trigger pause
            agg_report_bad = AggregateReport(
                query_id="test_query_id",
                query_data="test_data",
                value="0x0000000000000000000000000000000000000000000000001bc16d674ec80000",  # Large value
                aggregate_power="20",  # Low power
                micro_report_height="100"
            )
            
            # With power thresholds enabled
            result = await inspect_aggregate_report(
                agg_report_bad,
                mock_config_watcher,
                mock_logger,
                mock_threshold_config,
                "localhost:26657",  # URI provided
                power_thresholds      # Power thresholds provided
            )
            
            assert result is not None
            should_pause, reason, power_info = result
            # Should NOT pause despite exceeding traditional pause_threshold because power is too low
            assert should_pause is False
            assert "Power: 25.0%" in reason
            assert "NO PAUSE" in reason
            assert power_info is not None
            
            # Test without power thresholds (traditional logic)
            result_traditional = await inspect_aggregate_report(
                agg_report_bad,
                mock_config_watcher,
                mock_logger,
                mock_threshold_config,
                None,  # No URI
                None   # No power thresholds
            )
            
            assert result_traditional is not None
            should_pause_trad, reason_trad = result_traditional
            # Should pause with traditional logic
            assert should_pause_trad is True
            assert "CIRCUIT BREAKER ACTIVATED" in reason_trad