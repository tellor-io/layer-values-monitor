"""Trusted value for TRBBridge query type."""

import logging

from layer_values_monitor.evm_connections import get_web3_connection

from telliot_core.apps.telliot_config import TelliotConfig
from web3 import Web3
from web3.contract import Contract


def decode_query_data(query_data: str) -> int | None:
    """Decode TRBBridge queryData to extract deposit ID.

    Based on the example queryData with descriptors:
    {"type":"TRBBridge","arg1":"true","arg2":"1"}

    Args:
        query_data: Hex string of the query data

    Returns:
        Deposit ID as integer, or None if decoding fails

    """
    try:
        # Remove 0x prefix if present
        if query_data.startswith("0x"):
            query_data = query_data[2:]

        # Convert hex to bytes
        data_bytes = bytes.fromhex(query_data)

        # Based on the provided example, the queryData structure contains:
        # - Query type string "TRBBridge"
        # - Parameters including arg1="true" and arg2="1" (deposit ID)

        # The example shows arg2="1" which should be the deposit ID
        # From the hex data, we need to extract the deposit ID parameter
        # Looking at the pattern, the last 32 bytes should contain the deposit ID

        # Extract deposit ID from the last 32-byte word
        deposit_id = int.from_bytes(data_bytes[-32:], byteorder="big")

        return deposit_id
    except Exception as e:
        logging.error(f"Failed to decode TRBBridge queryData: {e}")
        return None


def decode_report_value(value_hex: str) -> tuple[str, str, int, int] | None:
    """Decode TRBBridge report value to extract deposit details.

    Based on the example value from encodeReport function:
    encodeReport(address _ethAddress, string calldata _layerAddress, uint256 _amount, uint256 _tip)

    Example:
    - _ethAddress: 0xAE7CFe4CF579Ec060f95d951bD5260A5A8c0dcDC
    - _layerAddress: "tellor168hv5trkskdwvxj2hzqdmch7r7l0prlnepslrz"
    - _amount: 1000000000000000000 (1 ETH in wei)
    - _tip: 100000000

    Args:
        value_hex: Hex string of the reported value

    Returns:
        Tuple of (eth_address, layer_address, amount, tip) or None if decoding fails

    """
    try:
        # Remove 0x prefix if present
        if value_hex.startswith("0x"):
            value_hex = value_hex[2:]

        # Convert hex to bytes
        value_bytes = bytes.fromhex(value_hex)

        # ABI decode the report value: (address, string, uint256, uint256)
        # Structure: address (32 bytes), string offset (32 bytes), amount (32 bytes), tip (32 bytes), string data

        # Extract address (bytes 0-32, but address is in the last 20 bytes)
        eth_address = "0x" + value_bytes[12:32].hex()

        # Extract string offset (bytes 32-64)
        string_offset = int.from_bytes(value_bytes[32:64], byteorder="big")

        # Extract amount (bytes 64-96)
        amount = int.from_bytes(value_bytes[64:96], byteorder="big")

        # Extract tip (bytes 96-128)
        tip = int.from_bytes(value_bytes[96:128], byteorder="big")

        # Extract layer address string
        # Get string length from the offset position
        string_length = int.from_bytes(value_bytes[string_offset : string_offset + 32], byteorder="big")
        # Get string data
        layer_address = value_bytes[string_offset + 32 : string_offset + 32 + string_length].decode("utf-8").rstrip("\x00")

        return eth_address.lower(), layer_address, amount, tip
    except Exception as e:
        logging.error(f"Failed to decode TRBBridge report value: {e}")
        return None


async def get_trb_bridge_trusted_value(
    query_data: str, contract_address: str, chain_id: int = 1, rpc_url: str = None, logger: logging.Logger = None
) -> tuple[str, str, int, int] | None:
    """Get trusted value for TRBBridge query type by reading from deposits mapping.

    Args:
        query_data: The query data containing deposit ID
        contract_address: Address of the TRBBridge contract
        chain_id: Chain ID for the contract (default: 1 for Ethereum mainnet)
        rpc_url: RPC URL for the bridge contract chain (if None, uses TelliotConfig)
        logger: Logger instance

    Returns:
        Tuple of (eth_address, layer_address, amount, tip) from contract, or None if failed

    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Decode deposit ID from query data
    deposit_id = decode_query_data(query_data)
    if deposit_id is None:
        logger.error("Failed to decode deposit ID from query data")
        return None

    logger.info(f"Checking TRBBridge deposit ID: {deposit_id}")

    try:
        # Set up Web3 connection using unified connection manager
        # Priority: custom rpc_url param > EVM_RPC_URLS_{chain_id} > BRIDGE_CHAIN_RPC_URL (deprecated) > TelliotConfig
        w3 = get_web3_connection(chain_id, custom_rpc_url=rpc_url, required=False)

        if not w3:
            # Final fallback to TelliotConfig
            logger.info(f"Falling back to TelliotConfig for chain {chain_id}")
            cfg = TelliotConfig()
            cfg.main.chain_id = chain_id
            endpoint = cfg.get_endpoint()
            endpoint.connect()
            w3: Web3 = endpoint.web3

        # Contract ABI for deposits mapping
        # Based on: mapping(uint256 depositId => DepositDetails) public deposits;
        # where DepositDetails(address sender, string layerRecipient, uint256 amount, uint256 tip, uint256 blockNumber)
        deposits_abi = [
            {
                "inputs": [{"name": "depositId", "type": "uint256"}],
                "name": "deposits",
                "outputs": [
                    {"name": "sender", "type": "address"},
                    {"name": "layerRecipient", "type": "string"},
                    {"name": "amount", "type": "uint256"},
                    {"name": "tip", "type": "uint256"},
                    {"name": "blockNumber", "type": "uint256"},
                ],
                "stateMutability": "view",
                "type": "function",
            }
        ]

        # Create contract instance
        contract: Contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=deposits_abi)

        # Call deposits mapping
        try:
            deposit_details = contract.functions.deposits(deposit_id).call()
            sender, layer_recipient, amount, tip, block_number = deposit_details

            logger.info(
                f"Retrieved deposit details - Sender: {sender}, Layer_Addr: {layer_recipient}, "
                f"Amount: {amount}, Tip: {tip}, Block Number: {block_number}"
            )

            return sender.lower(), layer_recipient, amount, tip

        except Exception as e:
            logger.error(f"Failed to call deposits mapping for deposit ID {deposit_id}: {e}")
            return None

    except Exception as e:
        logger.error(f"Failed to connect to Web3 endpoint for chain {chain_id}: {e}")
        return None
