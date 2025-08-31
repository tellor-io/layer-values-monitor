"""Tests for RPC URL validation functionality."""

import pytest
from unittest.mock import MagicMock, patch

from layer_values_monitor.main import validate_rpc_url


class TestRPCValidation:
    """Test cases for RPC URL validation."""

    def test_validate_saga_rpc_success(self):
        """Test successful Saga RPC validation."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 12345
            mock_w3.eth.chain_id = 1338  # Custom Saga chain ID
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://chainlet-2742.saga.xyz/", "Saga")

            assert is_valid is True
            assert error_msg == ""

    def test_validate_ethereum_mainnet_success(self):
        """Test successful Ethereum mainnet RPC validation."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 18500000
            mock_w3.eth.chain_id = 1  # Ethereum mainnet
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://mainnet.infura.io/v3/key", "Ethereum")

            assert is_valid is True
            assert error_msg == ""

    def test_validate_ethereum_sepolia_success(self):
        """Test successful Ethereum Sepolia RPC validation."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 4500000
            mock_w3.eth.chain_id = 11155111  # Sepolia testnet
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://sepolia.infura.io/v3/key", "Ethereum")

            assert is_valid is True
            assert error_msg == ""

    def test_validate_ethereum_unsupported_chain(self):
        """Test Ethereum RPC validation with unsupported chain ID."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 100000
            mock_w3.eth.chain_id = 137  # Polygon mainnet (unsupported)
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://polygon-rpc.com", "Ethereum")

            assert is_valid is False
            assert "Unsupported Ethereum chain ID 137" in error_msg
            assert "Supported: 1 (mainnet), 11155111 (sepolia)" in error_msg

    def test_validate_saga_invalid_chain_id(self):
        """Test Saga RPC validation with invalid chain ID."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 100000
            mock_w3.eth.chain_id = 0  # Invalid chain ID
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://bad-saga.com/", "Saga")

            assert is_valid is False
            assert "Invalid chain ID 0 for Saga network" in error_msg

    def test_validate_rpc_connection_failure(self):
        """Test RPC validation with connection failure."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = Exception("Connection failed")
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://invalid-url.com/", "Ethereum")

            assert is_valid is False
            assert "Failed to connect to Ethereum RPC" in error_msg
            assert "https://invalid-url.com/" in error_msg

    def test_validate_rpc_web3_creation_failure(self):
        """Test RPC validation when Web3 creation fails."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_web3_class.side_effect = Exception("Invalid RPC URL format")

            is_valid, error_msg = validate_rpc_url("invalid-url", "Saga")

            assert is_valid is False
            assert "Failed to connect to Saga RPC" in error_msg
            assert "invalid-url" in error_msg

    def test_validate_rpc_chain_id_access_failure(self):
        """Test RPC validation when chain_id access fails."""
        with patch("layer_values_monitor.main.Web3") as mock_web3_class:
            mock_w3 = MagicMock()
            mock_w3.eth.block_number = 12345  # This works
            mock_w3.eth.chain_id = Exception("Chain ID access failed")  # This fails
            mock_web3_class.return_value = mock_w3

            is_valid, error_msg = validate_rpc_url("https://rpc.com/", "Ethereum")

            assert is_valid is False
            assert "Failed to connect to Ethereum RPC" in error_msg