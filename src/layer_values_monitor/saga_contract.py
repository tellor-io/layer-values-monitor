"""Saga contract interactions for pausing contracts when circuit breaker is triggered."""

import logging
import os

from web3 import Web3


class SagaContractManager:
    """Manages interactions with Saga EVM contracts for pausing functionality."""

    def __init__(self, rpc_url: str, private_key: str, logger: logging.Logger) -> None:
        """Initialize the Saga contract manager.

        Args:
            rpc_url: The Saga EVM RPC endpoint
            private_key: Private key for signing transactions (without 0x prefix)
            logger: Logger instance

        """
        self.logger = logger
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

        # Setup account for signing
        if private_key.startswith("0x"):
            private_key = private_key[2:]
        self.account = self.w3.eth.account.from_key(private_key)

        # GuardedPausable contract ABI - core functions we need
        self.guarded_pausable_abi = [
            {"inputs": [], "name": "pause", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
            {"inputs": [], "name": "unpause", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
            {
                "inputs": [],
                "name": "paused",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [{"internalType": "address", "name": "", "type": "address"}],
                "name": "guardians",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function",
            },
        ]

        self.logger.info(f"Initialized Saga contract manager with account: {self.account.address}")

    async def pause_contract(self, contract_address: str, query_id: str) -> tuple[str | None, str]:
        """Pause a Saga contract by calling its pause() function.

        Args:
            contract_address: The contract address to pause
            query_id: Query ID for logging purposes

        Returns:
            Tuple of (transaction_hash, status_message).
            transaction_hash is str if successful, None if failed.
            status_message describes the result.

        """
        try:
            # Validate contract address format
            if not self.w3.is_address(contract_address):
                self.logger.error(f"Invalid contract address format: {contract_address}")
                return None, "invalid_address"

            # Convert to checksum address
            contract_address = self.w3.to_checksum_address(contract_address)

            # Create contract instance
            contract = self.w3.eth.contract(address=contract_address, abi=self.guarded_pausable_abi)

            # Check if contract exists
            if self.w3.eth.get_code(contract_address) == b"":
                self.logger.error(f"No contract found at address: {contract_address}")
                return None, "no_contract"

            # Check if account is a guardian
            is_guardian = await self.is_guardian(contract_address, self.account.address)
            if not is_guardian:
                self.logger.error(f"Account {self.account.address} is not a guardian for contract {contract_address}")
                return None, "not_guardian"

            # Check if contract is already paused
            is_paused = await self.is_paused(contract_address)
            if is_paused:
                self.logger.warning(f"Contract {contract_address} is already paused")
                return None, "already_paused"

            # Get current nonce
            nonce = self.w3.eth.get_transaction_count(self.account.address)

            # Build transaction
            transaction = contract.functions.pause().build_transaction(
                {
                    "from": self.account.address,
                    "nonce": nonce,
                    "gas": 100000,  # Conservative gas limit for a simple pause function
                    "gasPrice": self.w3.eth.gas_price,
                }
            )

            # Sign transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key=self.account.key)

            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()

            self.logger.critical(
                f"🚨 PAUSE TRANSACTION SENT - Query: {query_id[:16]}... Contract: {contract_address} TxHash: {tx_hash_hex}"
            )

            # Wait for transaction receipt (with timeout)
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=90)
                if receipt.status == 1:
                    self.logger.critical(
                        f"✅ PAUSE SUCCESSFUL - Contract {contract_address} paused successfully. TxHash: {tx_hash_hex}"
                    )
                    return tx_hash_hex, "success"
                else:
                    self.logger.error(
                        f"❌ PAUSE FAILED - Transaction failed for contract {contract_address}. TxHash: {tx_hash_hex}"
                    )
                    return None, "transaction_failed"
            except TimeoutError:
                self.logger.warning(
                    f"⏰ PAUSE PENDING - Transaction timeout for contract {contract_address}, "
                    f"but may still be processing. TxHash: {tx_hash_hex}"
                )
                return tx_hash_hex, "timeout"  # Return hash even on timeout as it may still succeed

        except Exception as e:
            self.logger.error(
                f"❌ PAUSE ERROR - Failed to pause contract {contract_address} for query {query_id[:16]}...: {e}"
            )
            return None, f"error: {str(e)}"

    async def is_guardian(self, contract_address: str, guardian_address: str) -> bool:
        """Check if an address is a guardian for the specified contract.

        Args:
            contract_address: The contract address to check
            guardian_address: The address to check guardian status for

        Returns:
            True if the address is a guardian, False otherwise

        """
        try:
            contract_address = self.w3.to_checksum_address(contract_address)
            guardian_address = self.w3.to_checksum_address(guardian_address)

            contract = self.w3.eth.contract(address=contract_address, abi=self.guarded_pausable_abi)

            return contract.functions.guardians(guardian_address).call()
        except Exception as e:
            self.logger.error(f"Failed to check guardian status for {guardian_address} on contract {contract_address}: {e}")
            return False

    async def is_paused(self, contract_address: str) -> bool:
        """Check if a contract is currently paused.

        Args:
            contract_address: The contract address to check

        Returns:
            True if the contract is paused, False otherwise

        """
        try:
            contract_address = self.w3.to_checksum_address(contract_address)

            contract = self.w3.eth.contract(address=contract_address, abi=self.guarded_pausable_abi)

            return contract.functions.paused().call()
        except Exception as e:
            self.logger.error(f"Failed to check pause status for contract {contract_address}: {e}")
            return False

    def is_connected(self) -> bool:
        """Check if Web3 connection is working."""
        try:
            _ = self.w3.eth.block_number
            return True
        except Exception as e:
            self.logger.error(f"Saga EVM connection failed: {e}")
            return False


def create_saga_contract_manager(logger: logging.Logger) -> SagaContractManager | None:
    """Create SagaContractManager from environment variables.

    Args:
        logger: Logger instance

    Returns:
        SagaContractManager instance if environment variables are set, None otherwise

    """
    saga_rpc_url = os.getenv("SAGA_EVM_RPC_URL")
    saga_private_key = os.getenv("SAGA_PRIVATE_KEY")

    if not saga_rpc_url:
        logger.warning("SAGA_EVM_RPC_URL not set in environment - contract pausing disabled")
        return None

    if not saga_private_key:
        logger.warning("SAGA_PRIVATE_KEY not set in environment - contract pausing disabled")
        return None

    try:
        manager = SagaContractManager(saga_rpc_url, saga_private_key, logger)
        if manager.is_connected():
            return manager
        else:
            logger.error("Failed to connect to Saga EVM - contract pausing disabled")
            return None
    except Exception as e:
        logger.error(f"Failed to initialize Saga contract manager: {e}")
        return None
