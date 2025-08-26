"""Tests for custom feeds functionality."""

import logging
import os
from unittest.mock import MagicMock, patch

from layer_values_monitor.custom_feeds import get_custom_trusted_value

import pytest


@pytest.fixture
def mock_logger():
    """Mock logger for testing."""
    return MagicMock(spec=logging.Logger)


class TestGetCustomTrustedValue:
    """Test cases for get_custom_trusted_value function."""

    @pytest.mark.asyncio
    async def test_unsupported_query_id_returns_none(self, mock_logger):
        """Test that unsupported query IDs return None."""
        result = await get_custom_trusted_value("invalid_query_id", mock_logger)
        assert result is None
        mock_logger.error.assert_called_once_with(
            "Query ID invalid_query_id is not configured for custom price lookup"
        )

    @pytest.mark.asyncio
    @patch.dict(os.environ, {}, clear=True)
    async def test_no_api_keys_returns_none(self, mock_logger):
        """Test that function returns None when no API keys are available."""
        fbtc_query_id = "c444759b83c7bb0f6694306e1f719e65679d48ad754a31d3a366856becf1e71e"
        result = await get_custom_trusted_value(fbtc_query_id, mock_logger)
        
        assert result is None
        mock_logger.error.assert_called_with("No valid FBTC/USD prices obtained from any source")



class TestCustomFeedsIntegration:
    """Integration tests that make real API calls (requires API keys)."""

    @pytest.mark.asyncio
    async def test_real_fbtc_price_fetch(self, mock_logger):
        """Integration test for real FBTC price fetching."""
        if not os.getenv("CMC_API_KEY") and not os.getenv("CG_API_KEY"):
            pytest.skip("No API keys available for integration testing")
        
        fbtc_query_id = "c444759b83c7bb0f6694306e1f719e65679d48ad754a31d3a366856becf1e71e"
        result = await get_custom_trusted_value(fbtc_query_id, mock_logger)
        
        if result is not None:
            # Price should be a positive number (reasonable range for FBTC)
            assert isinstance(result, float)
            assert result > 0
            assert result < 500000  # Sanity check - FBTC shouldn't be more than $500k
            print(f"FBTC/USD price: ${result:.2f}")
        else:
            pytest.skip("API calls failed - check API keys and network connectivity")

    @pytest.mark.asyncio
    async def test_real_saga_price_fetch(self, mock_logger):
        """Integration test for real SAGA price fetching."""
        if not os.getenv("CMC_API_KEY") and not os.getenv("CG_API_KEY"):
            pytest.skip("No API keys available for integration testing")
        
        saga_query_id = "74c9cfdfd2e4a00a9437bf93bf6051e18e604a976f3fa37faafe0bb5a039431d"
        result = await get_custom_trusted_value(saga_query_id, mock_logger)
        
        if result is not None:
            # Price should be a positive number (reasonable range for SAGA)
            assert isinstance(result, float)
            assert result > 0
            assert result < 1000  # Sanity check - SAGA shouldn't be more than $1000
            print(f"SAGA/USD price: ${result:.6f}")
        else:
            pytest.skip("API calls failed - check API keys and network connectivity")