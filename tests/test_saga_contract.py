"""Tests for Saga contract pausing functionality."""

import asyncio
import logging
import os
from unittest.mock import AsyncMock, MagicMock, Mock, PropertyMock, patch
from web3 import Web3
from web3.exceptions import Web3Exception

import pytest

from layer_values_monitor.saga_contract import SagaContractManager, create_saga_contract_manager


class TestSagaContractManager:
    """Test cases for SagaContractManager class."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger for testing."""
        return MagicMock(spec=logging.Logger)

    @pytest.fixture
    def mock_web3(self):
        """Create a mock Web3 instance."""
        mock_w3 = MagicMock(spec=Web3)
        mock_w3.eth = MagicMock()
        mock_w3.eth.block_number = 12345678
        mock_w3.eth.gas_price = 20000000000  # 20 gwei
        mock_w3.is_address.return_value = True
        mock_w3.to_checksum_address.side_effect = lambda x: x.upper()
        mock_w3.eth.get_code.return_value = b'some_contract_code'
        mock_w3.eth.get_transaction_count.return_value = 5
        return mock_w3

    @pytest.fixture
    def mock_account(self):
        """Create a mock account."""
        account = MagicMock()
        account.address = "0x742d35Cc6634C0532925a3b8D404d8E3c3dd542B"
        account.key = b'test_private_key'
        return account

    @pytest.fixture
    def saga_manager(self, mock_logger, mock_web3, mock_account):
        """Create a SagaContractManager instance with mocked dependencies."""
        with patch('layer_values_monitor.saga_contract.Web3') as mock_web3_class:
            mock_web3_class.return_value = mock_web3
            with patch('layer_values_monitor.saga_contract.Web3.eth.account.from_key') as mock_from_key:
                mock_from_key.return_value = mock_account
                manager = SagaContractManager(
                    "https://chainlet-2742.saga.xyz/",
                    "test_private_key",
                    mock_logger
                )
                manager.w3 = mock_web3
                manager.account = mock_account
                return manager

    def test_initialization_success(self, mock_logger):
        """Test successful initialization of SagaContractManager."""
        with patch('layer_values_monitor.saga_contract.Web3') as mock_web3_class:
            mock_web3 = MagicMock()
            mock_web3_class.return_value = mock_web3
            mock_web3.eth.account.from_key = MagicMock()
            
            mock_account = MagicMock()
            mock_account.address = "0x742d35Cc6634C0532925a3b8D404d8E3c3dd542B"
            mock_web3.eth.account.from_key.return_value = mock_account
            
            manager = SagaContractManager(
                "https://chainlet-2742.saga.xyz/",
                "0xtest_private_key",
                mock_logger
            )
            
            assert manager.logger == mock_logger
            mock_logger.info.assert_called_once()

    def test_initialization_strips_0x_prefix(self, mock_logger):
        """Test that 0x prefix is stripped from private key."""
        with patch('layer_values_monitor.saga_contract.Web3') as mock_web3_class:
            mock_web3 = MagicMock()
            mock_web3_class.return_value = mock_web3
            mock_web3.eth.account.from_key = MagicMock()
            mock_web3.eth.account.from_key.return_value = MagicMock()
            
            SagaContractManager(
                "https://chainlet-2742.saga.xyz/",
                "0xtest_private_key",
                mock_logger
            )
            
            # Should be called with key without 0x prefix
            mock_web3.eth.account.from_key.assert_called_once_with("test_private_key")

    @pytest.mark.asyncio
    async def test_pause_contract_success(self, saga_manager, mock_logger, mock_web3):
        """Test successful contract pausing."""
        # Setup mocks
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        
        # Mock guardian check
        mock_contract.functions.guardians.return_value.call.return_value = True
        
        # Mock pause check
        mock_contract.functions.paused.return_value.call.return_value = False
        
        # Mock transaction building and sending
        mock_transaction = {
            'from': saga_manager.account.address,
            'nonce': 5,
            'gas': 100000,
            'gasPrice': 20000000000,
        }
        mock_contract.functions.pause.return_value.build_transaction.return_value = mock_transaction
        
        # Mock signing and sending
        mock_signed_txn = MagicMock()
        mock_signed_txn.rawTransaction = b'signed_transaction_data'
        
        with patch.object(saga_manager.w3.eth.account, 'sign_transaction', return_value=mock_signed_txn):
            mock_web3.eth.send_raw_transaction.return_value.hex.return_value = "0xtest_hash"
            
            # Mock receipt
            mock_receipt = MagicMock()
            mock_receipt.status = 1
            mock_web3.eth.wait_for_transaction_receipt.return_value = mock_receipt
            
            result = await saga_manager.pause_contract(
                "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
                "test_query_id"
            )
            
            assert result == "0xtest_hash"
            mock_logger.critical.assert_called()

    @pytest.mark.asyncio
    async def test_pause_contract_invalid_address(self, saga_manager, mock_logger, mock_web3):
        """Test pause contract with invalid address."""
        mock_web3.is_address.return_value = False
        
        result = await saga_manager.pause_contract(
            "invalid_address",
            "test_query_id"
        )
        
        assert result is None
        mock_logger.error.assert_called_with("Invalid contract address format: invalid_address")

    @pytest.mark.asyncio
    async def test_pause_contract_no_code(self, saga_manager, mock_logger, mock_web3):
        """Test pause contract when no contract exists at address."""
        mock_web3.eth.get_code.return_value = b''
        
        result = await saga_manager.pause_contract(
            "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
            "test_query_id"
        )
        
        assert result is None
        mock_logger.error.assert_called_with("No contract found at address: 0X9FE237B245466A5F088AFE808B27C1305E3027BC")

    @pytest.mark.asyncio
    async def test_pause_contract_not_guardian(self, saga_manager, mock_logger, mock_web3):
        """Test pause contract when account is not a guardian."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        
        # Mock guardian check returning False
        with patch.object(saga_manager, 'is_guardian', return_value=False):
            result = await saga_manager.pause_contract(
                "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
                "test_query_id"
            )
            
            assert result is None
            mock_logger.error.assert_called_with(
                f"Account {saga_manager.account.address} is not a guardian for contract 0X9FE237B245466A5F088AFE808B27C1305E3027BC"
            )

    @pytest.mark.asyncio
    async def test_pause_contract_already_paused(self, saga_manager, mock_logger, mock_web3):
        """Test pause contract when contract is already paused."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        
        # Mock checks
        with patch.object(saga_manager, 'is_guardian', return_value=True):
            with patch.object(saga_manager, 'is_paused', return_value=True):
                result = await saga_manager.pause_contract(
                    "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
                    "test_query_id"
                )
                
                assert result is None
                mock_logger.warning.assert_called_with("Contract 0X9FE237B245466A5F088AFE808B27C1305E3027BC is already paused")

    @pytest.mark.asyncio
    async def test_pause_contract_transaction_failure(self, saga_manager, mock_logger, mock_web3):
        """Test pause contract when transaction fails."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        
        # Mock successful checks
        with patch.object(saga_manager, 'is_guardian', return_value=True):
            with patch.object(saga_manager, 'is_paused', return_value=False):
                # Mock transaction failure
                mock_web3.eth.send_raw_transaction.side_effect = Web3Exception("Transaction failed")
                
                result = await saga_manager.pause_contract(
                    "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
                    "test_query_id"
                )
                
                assert result is None
                mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_pause_contract_receipt_failure(self, saga_manager, mock_logger, mock_web3):
        """Test pause contract when transaction receipt shows failure."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        
        # Mock successful checks
        with patch.object(saga_manager, 'is_guardian', return_value=True):
            with patch.object(saga_manager, 'is_paused', return_value=False):
                # Mock transaction building and sending
                mock_transaction = {
                    'from': saga_manager.account.address,
                    'nonce': 5,
                    'gas': 100000,
                    'gasPrice': 20000000000,
                }
                mock_contract.functions.pause.return_value.build_transaction.return_value = mock_transaction
                
                # Mock signing and sending
                mock_signed_txn = MagicMock()
                mock_signed_txn.rawTransaction = b'signed_transaction_data'
                
                with patch.object(saga_manager.w3.eth.account, 'sign_transaction', return_value=mock_signed_txn):
                    mock_web3.eth.send_raw_transaction.return_value.hex.return_value = "0xtest_hash"
                    
                    # Mock failed receipt
                    mock_receipt = MagicMock()
                    mock_receipt.status = 0  # Failed
                    mock_web3.eth.wait_for_transaction_receipt.return_value = mock_receipt
                    
                    result = await saga_manager.pause_contract(
                        "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
                        "test_query_id"
                    )
                    
                    assert result is None
                    mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_pause_contract_timeout(self, saga_manager, mock_logger, mock_web3):
        """Test pause contract when transaction times out."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        
        # Mock successful checks
        with patch.object(saga_manager, 'is_guardian', return_value=True):
            with patch.object(saga_manager, 'is_paused', return_value=False):
                # Mock transaction building and sending
                mock_transaction = {
                    'from': saga_manager.account.address,
                    'nonce': 5,
                    'gas': 100000,
                    'gasPrice': 20000000000,
                }
                mock_contract.functions.pause.return_value.build_transaction.return_value = mock_transaction
                
                # Mock signing and sending
                mock_signed_txn = MagicMock()
                mock_signed_txn.rawTransaction = b'signed_transaction_data'
                
                with patch.object(saga_manager.w3.eth.account, 'sign_transaction', return_value=mock_signed_txn):
                    mock_web3.eth.send_raw_transaction.return_value.hex.return_value = "0xtest_hash"
                    
                    # Mock timeout
                    mock_web3.eth.wait_for_transaction_receipt.side_effect = asyncio.TimeoutError()
                    
                    result = await saga_manager.pause_contract(
                        "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
                        "test_query_id"
                    )
                    
                    assert result == "0xtest_hash"  # Should still return hash on timeout
                    mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_is_guardian_success(self, saga_manager, mock_web3):
        """Test successful guardian status check."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        mock_contract.functions.guardians.return_value.call.return_value = True
        
        result = await saga_manager.is_guardian(
            "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
            "0x742d35Cc6634C0532925a3b8D404d8E3c3dd542B"
        )
        
        assert result is True

    @pytest.mark.asyncio
    async def test_is_guardian_false(self, saga_manager, mock_web3):
        """Test guardian status check returning false."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        mock_contract.functions.guardians.return_value.call.return_value = False
        
        result = await saga_manager.is_guardian(
            "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
            "0x742d35Cc6634C0532925a3b8D404d8E3c3dd542B"
        )
        
        assert result is False

    @pytest.mark.asyncio
    async def test_is_guardian_exception(self, saga_manager, mock_logger, mock_web3):
        """Test guardian status check with exception."""
        mock_web3.eth.contract.side_effect = Exception("Contract error")
        
        result = await saga_manager.is_guardian(
            "0x9fe237b245466A5f088AfE808b27c1305E3027BC",
            "0x742d35Cc6634C0532925a3b8D404d8E3c3dd542B"
        )
        
        assert result is False
        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_is_paused_true(self, saga_manager, mock_web3):
        """Test pause status check returning true."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        mock_contract.functions.paused.return_value.call.return_value = True
        
        result = await saga_manager.is_paused("0x9fe237b245466A5f088AfE808b27c1305E3027BC")
        
        assert result is True

    @pytest.mark.asyncio
    async def test_is_paused_false(self, saga_manager, mock_web3):
        """Test pause status check returning false."""
        mock_contract = MagicMock()
        mock_web3.eth.contract.return_value = mock_contract
        mock_contract.functions.paused.return_value.call.return_value = False
        
        result = await saga_manager.is_paused("0x9fe237b245466A5f088AfE808b27c1305E3027BC")
        
        assert result is False

    @pytest.mark.asyncio
    async def test_is_paused_exception(self, saga_manager, mock_logger, mock_web3):
        """Test pause status check with exception."""
        mock_web3.eth.contract.side_effect = Exception("Contract error")
        
        result = await saga_manager.is_paused("0x9fe237b245466A5f088AfE808b27c1305E3027BC")
        
        assert result is False
        mock_logger.error.assert_called()

    def test_is_connected_success(self, saga_manager, mock_web3):
        """Test successful connection check."""
        result = saga_manager.is_connected()
        assert result is True

    def test_is_connected_failure(self, saga_manager, mock_logger, mock_web3):
        """Test connection check with failure."""
        # Create a property that raises an exception when accessed
        type(mock_web3.eth).block_number = PropertyMock(side_effect=Exception("Connection error"))
        
        result = saga_manager.is_connected()
        
        assert result is False
        mock_logger.error.assert_called()


class TestCreateSagaContractManager:
    """Test cases for create_saga_contract_manager factory function."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock logger for testing."""
        return MagicMock(spec=logging.Logger)

    def test_create_success(self, mock_logger):
        """Test successful creation of SagaContractManager."""
        with patch.dict(os.environ, {
            'SAGA_EVM_RPC_URL': 'https://chainlet-2742.saga.xyz/',
            'SAGA_PRIVATE_KEY': 'test_private_key'
        }):
            with patch('layer_values_monitor.saga_contract.SagaContractManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.is_connected.return_value = True
                mock_manager_class.return_value = mock_manager
                
                result = create_saga_contract_manager(mock_logger)
                
                assert result == mock_manager
                mock_manager_class.assert_called_once_with(
                    'https://chainlet-2742.saga.xyz/',
                    'test_private_key',
                    mock_logger
                )

    def test_create_missing_rpc_url(self, mock_logger):
        """Test creation with missing RPC URL."""
        with patch.dict(os.environ, {
            'SAGA_PRIVATE_KEY': 'test_private_key'
        }, clear=True):
            result = create_saga_contract_manager(mock_logger)
            
            assert result is None
            mock_logger.warning.assert_called_with(
                "SAGA_EVM_RPC_URL not set in environment - contract pausing disabled"
            )

    def test_create_missing_private_key(self, mock_logger):
        """Test creation with missing private key."""
        with patch.dict(os.environ, {
            'SAGA_EVM_RPC_URL': 'https://chainlet-2742.saga.xyz/'
        }, clear=True):
            result = create_saga_contract_manager(mock_logger)
            
            assert result is None
            mock_logger.warning.assert_called_with(
                "SAGA_PRIVATE_KEY not set in environment - contract pausing disabled"
            )

    def test_create_connection_failure(self, mock_logger):
        """Test creation with connection failure."""
        with patch.dict(os.environ, {
            'SAGA_EVM_RPC_URL': 'https://chainlet-2742.saga.xyz/',
            'SAGA_PRIVATE_KEY': 'test_private_key'
        }):
            with patch('layer_values_monitor.saga_contract.SagaContractManager') as mock_manager_class:
                mock_manager = MagicMock()
                mock_manager.is_connected.return_value = False
                mock_manager_class.return_value = mock_manager
                
                result = create_saga_contract_manager(mock_logger)
                
                assert result is None
                mock_logger.error.assert_called_with(
                    "Failed to connect to Saga EVM - contract pausing disabled"
                )

    def test_create_initialization_exception(self, mock_logger):
        """Test creation with initialization exception."""
        with patch.dict(os.environ, {
            'SAGA_EVM_RPC_URL': 'https://chainlet-2742.saga.xyz/',
            'SAGA_PRIVATE_KEY': 'test_private_key'
        }):
            with patch('layer_values_monitor.saga_contract.SagaContractManager') as mock_manager_class:
                mock_manager_class.side_effect = Exception("Initialization failed")
                
                result = create_saga_contract_manager(mock_logger)
                
                assert result is None
                mock_logger.error.assert_called_with(
                    "Failed to initialize Saga contract manager: Initialization failed"
                )