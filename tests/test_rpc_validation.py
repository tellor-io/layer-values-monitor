"""Tests for RPC URL validation functionality.

These tests use both real network calls and mocked responses to validate the RPC validation logic.
Some tests may be skipped if network connectivity is unavailable.
"""

import pytest
from unittest.mock import MagicMock, patch

from layer_values_monitor.main import validate_rpc_url


class TestRPCValidation:
    """Test cases for RPC URL validation."""

    @pytest.mark.skipif(
        condition=False,  # Always run for now, can be made conditional later
        reason="Network test - requires internet connectivity"
    )
    def test_validate_saga_rpc_with_real_endpoint(self):
        """Test Saga RPC validation with a real public endpoint."""
        # Using the actual Saga endpoint from the env vars fixture
        is_valid, error_msg = validate_rpc_url("https://chainlet-2742.saga.xyz/", "Saga")
        
        # This should succeed if the endpoint is accessible
        # If it fails due to network issues, that's still a valid test
        if is_valid:
            assert error_msg == ""
        else:
            # If it fails, it should be due to network connectivity, not validation logic
            assert "Failed to connect to Saga RPC" in error_msg
            assert "https://chainlet-2742.saga.xyz/" in error_msg

    def test_validate_rpc_with_invalid_url(self):
        """Test RPC validation with completely invalid URL."""
        is_valid, error_msg = validate_rpc_url("not-a-url", "Ethereum")
        
        assert is_valid is False
        assert "Failed to connect to Ethereum RPC" in error_msg
        assert "not-a-url" in error_msg

    def test_validate_rpc_with_unreachable_host(self):
        """Test RPC validation with unreachable host."""
        is_valid, error_msg = validate_rpc_url("http://localhost:99999", "Saga")
        
        assert is_valid is False
        assert "Failed to connect to Saga RPC" in error_msg
        assert "localhost:99999" in error_msg

    def test_validate_with_malformed_urls(self):
        """Test RPC validation with various malformed URLs."""
        # Test various malformed URLs
        test_cases = [
            "ftp://wrong-protocol.com",
            "https://",
            "",
            "localhost:port",
        ]
        
        for bad_url in test_cases:
            is_valid, error_msg = validate_rpc_url(bad_url, "Ethereum")
            
            assert is_valid is False
            assert "Failed to connect to Ethereum RPC" in error_msg
            assert bad_url in error_msg

    def test_validate_ethereum_unsupported_chain_id(self):
        """Test Ethereum RPC validation with unsupported chain ID."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 100000
            mock_w3.eth.chain_id = 137  # Polygon mainnet (unsupported for Ethereum)
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://polygon-rpc.com", "Ethereum")

            assert is_valid is False
            assert "Unsupported Ethereum chain ID 137" in error_msg
            assert "Supported: 1 (mainnet), 11155111 (sepolia)" in error_msg

    def test_validate_saga_accepts_any_positive_chain_id(self):
        """Test Saga validation accepts any positive chain ID."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 12345
            mock_w3.eth.chain_id = 1338  # Custom Saga chain ID
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://saga-test.com/", "Saga")

            assert is_valid is True
            assert error_msg == ""

    def test_validate_saga_rejects_invalid_chain_id(self):
        """Test Saga validation rejects invalid chain IDs."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 12345
            mock_w3.eth.chain_id = 0  # Invalid chain ID
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://saga-test.com/", "Saga")

            assert is_valid is False
            assert "Invalid chain ID 0 for Saga network" in error_msg

    def test_validate_ethereum_accepts_mainnet(self):
        """Test Ethereum validation accepts mainnet."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 18000000
            mock_w3.eth.chain_id = 1  # Mainnet
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://mainnet.infura.io/v3/key", "Ethereum")

            assert is_valid is True
            assert error_msg == ""

    def test_validate_ethereum_accepts_sepolia(self):
        """Test Ethereum validation accepts Sepolia testnet."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 4000000
            mock_w3.eth.chain_id = 11155111  # Sepolia
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://sepolia.infura.io/v3/key", "Ethereum")

            assert is_valid is True
            assert error_msg == ""

    def test_validate_network_name_case_insensitive(self):
        """Test that network name matching is case insensitive for both networks."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 12345
            mock_w3.eth.chain_id = 1338
            mock_web3_class.return_value = mock_w3

            # Test different cases for Saga
            saga_cases = ["saga", "Saga", "SAGA", "SaGa"]
            for network_name in saga_cases:
                is_valid, error_msg = validate_rpc_url("https://test.com/", network_name)
                assert is_valid is True
                assert error_msg == ""

            # Test different cases for Ethereum  
            mock_w3.eth.chain_id = 1  # Ethereum mainnet
            ethereum_cases = ["ethereum", "Ethereum", "ETHEREUM", "EtHeReUm"]
            for network_name in ethereum_cases:
                is_valid, error_msg = validate_rpc_url("https://test.com/", network_name)
                assert is_valid is True
                assert error_msg == ""