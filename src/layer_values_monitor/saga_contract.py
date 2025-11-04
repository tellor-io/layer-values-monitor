"""Saga contract interactions for pausing contracts when circuit breaker is triggered."""

import logging

from layer_values_monitor.evm_connections import get_saga_web3_connection

from web3 import Web3


class SagaContractManager:
    """Manages interactions with Saga EVM contracts for pausing functionality."""

    def __init__(self, w3: Web3, private_key: str, logger: logging.Logger) -> None:
        """Initialize the Saga contract manager.

        Args:
            w3: Web3 instance connected to Saga EVM
            private_key: Private key for signing transactions (without 0x prefix)
            logger: Logger instance

        """
        self.logger = logger
        self.w3 = w3

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

        self.logger.info(f"💡 Initialized Saga contract manager with account: {self.account.address}")

    async def _execute_pause_transaction(
        self, contract_address: str, query_id: str, attempt: int = 1
    ) -> tuple[str | None, str]:
        """Execute a single pause transaction attempt.

        Args:
            contract_address: The contract address to pause (must be checksum format)
            query_id: Query ID for logging purposes
            attempt: Attempt number for logging

        Returns:
            Tuple of (transaction_hash, status_message).

        """
        try:
            # Create contract instance
            contract = self.w3.eth.contract(address=contract_address, abi=self.guarded_pausable_abi)

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

            attempt_suffix = f" (Attempt {attempt})" if attempt > 1 else ""
            self.logger.critical(
                f"🚨 PAUSE TRANSACTION SENT{attempt_suffix} - Query: {query_id[:16]}... "
                f"Contract: {contract_address} TxHash: {tx_hash_hex}"
            )

            # Wait for transaction receipt (with 90s timeout)
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=90)
                if receipt.status == 1:
                    self.logger.critical(
                        f"✅ PAUSE SUCCESSFUL{attempt_suffix} - Contract {contract_address} "
                        f"paused successfully. TxHash: {tx_hash_hex}"
                    )
                    return tx_hash_hex, "contract_paused_successfully"
                else:
                    self.logger.error(
                        f"❌ PAUSE FAILED{attempt_suffix} - Transaction failed for contract "
                        f"{contract_address}. TxHash: {tx_hash_hex}"
                    )
                    return None, "transaction_failed"
            except TimeoutError:
                self.logger.warning(
                    f"⏰ PAUSE CALL PENDING{attempt_suffix} - 90s timeout limit reached for contract {contract_address}, "
                    f"tx may still be processing. TxHash: {tx_hash_hex}"
                )
                return tx_hash_hex, "timeout"

        except Exception as e:
            attempt_suffix = f" (Attempt {attempt})" if attempt > 1 else ""
            self.logger.error(
                f"❌ PAUSE ERROR{attempt_suffix} - Failed to pause contract {contract_address} "
                f"for query {query_id[:16]}...: {e}"
            )
            return None, f"error: {str(e)}"

    async def pause_contract(self, contract_address: str, query_id: str, max_retries: int = 2) -> tuple[str | None, str]:
        """Pause a datafeed contract by calling its pause() function.

        Args:
            contract_address: The contract address to pause
            query_id: Query ID for logging purposes
            max_retries: Maximum number of retry attempts on timeout (default: 2)

        Returns:
            Tuple of (transaction_hash, status_message).
            transaction_hash is str if successful, None if failed.
            status_message describes the result.

        """
        try:
            # Validate contract address format
            if not self.w3.is_address(contract_address):
                self.logger.error(f"Invalid contract address format: {contract_address}")
                return None, "invalid_contract_address"

            # Convert to checksum address
            contract_address = self.w3.to_checksum_address(contract_address)

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

            # Execute pause transaction with retry logic
            for attempt in range(1, max_retries + 1):
                tx_hash, status = await self._execute_pause_transaction(contract_address, query_id, attempt)

                # Return immediately on success or non-timeout failures
                if status == "contract_paused_successfully" or status != "timeout":
                    return tx_hash, status

                # On timeout, check if we should retry
                if attempt < max_retries:
                    self.logger.warning(
                        f"🔄 RETRY PAUSE - Attempting retry {attempt + 1}/{max_retries} "
                        f"for contract {contract_address} due to timeout"
                    )
                    # Check if contract got paused during the timeout
                    is_paused_now = await self.is_paused(contract_address)
                    if is_paused_now:
                        self.logger.critical(
                            f"✅ PAUSE CONFIRMED - Contract {contract_address} was paused during timeout. "
                            f"Previous TxHash: {tx_hash}"
                        )
                        return tx_hash, "contract_paused_successfully"
                else:
                    # Final timeout
                    self.logger.error(
                        f"❌ PAUSE TIMEOUT - Final timeout after {max_retries} attempts "
                        f"for contract {contract_address}. Last TxHash: {tx_hash}"
                    )
                    return tx_hash, "final_timeout"

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

    Uses SAGA_EVM_RPC_URL for special Saga guardian handling (requires transaction signing).
    The connection is still cached in the global cache for potential reuse.

    Args:
        logger: Logger instance

    Returns:
        SagaContractManager instance if environment variables are set, None otherwise

    """
    import os
    
    # Get Web3 connection using unified manager (reads SAGA_EVM_RPC_URL)
    w3, chain_id = get_saga_web3_connection(logger)
    
    if not w3:
        return None

    saga_private_key = os.getenv("SAGA_PRIVATE_KEY")
    if not saga_private_key:
        logger.warning("SAGA_PRIVATE_KEY not set in environment - contract pausing disabled")
        return None

    try:
        manager = SagaContractManager(w3, saga_private_key, logger)
        if manager.is_connected():
            logger.info(f"✅ Saga contract manager initialized for chain {chain_id}")
            return manager
        else:
            logger.error("Failed to verify Saga EVM connection - contract pausing disabled")
            return None
    except Exception as e:
        logger.error(f"Failed to initialize Saga contract manager: {e}")
        return None
