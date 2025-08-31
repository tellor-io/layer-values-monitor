"""Integration tests for main.py RPC validation during startup."""

import os
from unittest.mock import patch

from layer_values_monitor.main import start

import pytest


class TestMainRPCValidation:
    """Test cases for RPC validation during main startup."""

    @pytest.fixture
    def base_env_vars(self):
        """Base environment variables needed for testing."""
        return {
            "URI": "localhost:26657",
            "CHAIN_ID": "layer-testnet-3",
            "LAYER_BINARY_PATH": "/path/to/layerd",
            "LAYER_KEY_NAME": "test-key",
            "LAYER_KEYRING_BACKEND": "test",
            "LAYER_KEYRING_DIR": "~/.layer",
        }

    @pytest.fixture
    def saga_env_vars(self):
        """Saga-specific environment variables."""
        return {
            "SAGA_EVM_RPC_URL": "https://chainlet-2742.saga.xyz/",
            "SAGA_PRIVATE_KEY": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        }

    def test_startup_with_valid_saga_rpc(self, base_env_vars, saga_env_vars):
        """Test successful startup with valid Saga RPC."""
        env_vars = {**base_env_vars, **saga_env_vars}

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("layer_values_monitor.main.validate_rpc_url") as mock_validate:
                mock_validate.return_value = (True, "")
                with patch("layer_values_monitor.main.asyncio.gather") as mock_gather:
                    mock_gather.side_effect = KeyboardInterrupt()  # Exit gracefully
                    with patch("sys.argv", ["main.py", "--enable-saga-guard"]):
                        # This should not raise an exception
                        start()

                # Verify RPC validation was called for Saga
                mock_validate.assert_called_with("https://chainlet-2742.saga.xyz/", "Saga")

    def test_startup_with_invalid_saga_rpc(self, base_env_vars, saga_env_vars):
        """Test startup failure with invalid Saga RPC."""
        env_vars = {**base_env_vars, **saga_env_vars}

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("layer_values_monitor.main.validate_rpc_url") as mock_validate:
                mock_validate.return_value = (False, "Connection failed")
                with patch("sys.argv", ["main.py", "--enable-saga-guard"]):
                    with pytest.raises(ValueError, match="Saga RPC validation failed: Connection failed"):
                        start()

    def test_startup_with_valid_saga_and_ethereum_rpc(self, base_env_vars, saga_env_vars):
        """Test successful startup with both Saga and Ethereum RPC validation."""
        env_vars = {
            **base_env_vars,
            **saga_env_vars,
            "ETHEREUM_RPC_URL": "https://sepolia.infura.io/v3/key",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("layer_values_monitor.main.validate_rpc_url") as mock_validate:
                mock_validate.return_value = (True, "")
                with patch("layer_values_monitor.main.asyncio.gather") as mock_gather:
                    mock_gather.side_effect = KeyboardInterrupt()  # Exit gracefully
                    with patch("sys.argv", ["main.py", "--enable-saga-guard"]):
                        start()

                # Verify RPC validation was called for both networks
                assert mock_validate.call_count == 2
                mock_validate.assert_any_call("https://chainlet-2742.saga.xyz/", "Saga")
                mock_validate.assert_any_call("https://sepolia.infura.io/v3/key", "Ethereum")

    def test_startup_with_invalid_ethereum_rpc(self, base_env_vars, saga_env_vars):
        """Test startup failure with invalid Ethereum RPC."""
        env_vars = {
            **base_env_vars,
            **saga_env_vars,
            "ETHEREUM_RPC_URL": "https://bad-ethereum-rpc.com/",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("layer_values_monitor.main.validate_rpc_url") as mock_validate:
                # First call (Saga) succeeds, second call (Ethereum) fails
                mock_validate.side_effect = [(True, ""), (False, "Invalid Ethereum RPC")]
                with patch("sys.argv", ["main.py", "--enable-saga-guard"]):
                    with pytest.raises(ValueError, match="Ethereum RPC validation failed: Invalid Ethereum RPC"):
                        start()

    def test_startup_without_saga_guard_no_validation(self, base_env_vars):
        """Test startup without --enable-saga-guard skips RPC validation."""
        with patch.dict(os.environ, base_env_vars, clear=True):
            with patch("layer_values_monitor.main.validate_rpc_url") as mock_validate:
                with patch("layer_values_monitor.main.asyncio.gather") as mock_gather:
                    mock_gather.side_effect = KeyboardInterrupt()  # Exit gracefully
                    with patch("sys.argv", ["main.py"]):
                        start()

                # Verify RPC validation was not called
                mock_validate.assert_not_called()

    def test_startup_saga_guard_missing_rpc_url(self, base_env_vars):
        """Test startup failure when SAGA_EVM_RPC_URL is missing."""
        env_vars = {
            **base_env_vars,
            "SAGA_PRIVATE_KEY": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("sys.argv", ["main.py", "--enable-saga-guard"]):
                with pytest.raises(ValueError, match="SAGA_EVM_RPC_URL environment variable is required"):
                    start()

    def test_startup_saga_guard_missing_private_key(self, base_env_vars):
        """Test startup failure when SAGA_PRIVATE_KEY is missing."""
        env_vars = {
            **base_env_vars,
            "SAGA_EVM_RPC_URL": "https://chainlet-2742.saga.xyz/",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("sys.argv", ["main.py", "--enable-saga-guard"]):
                with pytest.raises(ValueError, match="SAGA_PRIVATE_KEY environment variable is required"):
                    start()

    def test_startup_ethereum_rpc_only_no_validation_without_saga_guard(self, base_env_vars):
        """Test that Ethereum RPC is not validated when Saga guard is disabled."""
        env_vars = {
            **base_env_vars,
            "ETHEREUM_RPC_URL": "https://sepolia.infura.io/v3/key",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("layer_values_monitor.main.validate_rpc_url") as mock_validate:
                with patch("layer_values_monitor.main.asyncio.gather") as mock_gather:
                    mock_gather.side_effect = KeyboardInterrupt()  # Exit gracefully
                    with patch("sys.argv", ["main.py"]):
                        start()

                # Verify RPC validation was not called
                mock_validate.assert_not_called()
