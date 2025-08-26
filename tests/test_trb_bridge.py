"""Tests for TRBBridge monitoring functionality."""

from layer_values_monitor.trb_bridge import decode_query_data, decode_report_value, get_trb_bridge_trusted_value

import pytest


class TestTRBBridgeDecoding:
    """Test TRBBridge query data and report value decoding."""

    def test_decode_query_data(self):
        """Test decoding of TRBBridge queryData to extract deposit ID."""
        # Example queryData from the user
        query_data = (
            "0x0000000000000000000000000000000000000000000000000000000000000040"
            "000000000000000000000000000000000000000000000000000000000000008000"
            "0000000000000000000000000000000000000000000000000000000000095452424"
            "272696467650000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000004000000"
            "0000000000000000000000000000000000000000000000000000000000000001000000"
            "0000000000000000000000000000000000000000000000000000000000000001"
        )

        deposit_id = decode_query_data(query_data)

        # Based on the example descriptors {"type":"TRBBridge","arg1":"true","arg2":"1"}
        # The deposit ID should be 1
        assert deposit_id == 1

    def test_decode_report_value(self):
        """Test decoding of TRBBridge report value to extract deposit details."""
        # Example report value from the user
        value_hex = (
            "0x000000000000000000000000ae7cfe4cf579ec060f95d951bd5260a5a8c0dcdc"
            "000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000001b69b4bacd05f1500000000000000000000000000000000000000000000000000000000075bcd15000000000000000000000000000000000000000000000000000000000000002d74656c6c6f72317038386a7530796875746d6635703275373938787633756d616137756a77376763683972346600000000000000000000000000000000000000"
        )

        result = decode_report_value(value_hex)

        assert result is not None
        eth_address, layer_address, amount, tip = result

        # Expected values from the example
        assert eth_address == "0xae7cfe4cf579ec060f95d951bd5260a5a8c0dcdc"
        assert layer_address == "tellor1p88ju0yhutmf5p2u798xv3umaa7ujw7gch9r4f"
        assert amount == 123456789123456789
        assert tip == 123456789

    def test_decode_query_data_invalid_hex(self):
        """Test handling of invalid hex data."""
        invalid_query_data = "invalid_hex_data"

        deposit_id = decode_query_data(invalid_query_data)

        assert deposit_id is None

    def test_decode_report_value_invalid_hex(self):
        """Test handling of invalid hex data in report value."""
        invalid_value = "invalid_hex_data"

        result = decode_report_value(invalid_value)

        assert result is None

    def test_decode_query_data_with_0x_prefix(self):
        """Test that function handles both with and without 0x prefix."""
        query_data_with_prefix = (
            "0x0000000000000000000000000000000000000000000000000000000000000040"
            "000000000000000000000000000000000000000000000000000000000000008000"
            "0000000000000000000000000000000000000000000000000000000000095452424"
            "272696467650000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000004000000"
            "0000000000000000000000000000000000000000000000000000000000000001000000"
            "0000000000000000000000000000000000000000000000000000000000000009"
        )
        query_data_without_prefix = (
            "0000000000000000000000000000000000000000000000000000000000000040"
            "000000000000000000000000000000000000000000000000000000000000008000"
            "0000000000000000000000000000000000000000000000000000000000095452424"
            "272696467650000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000004000000"
            "0000000000000000000000000000000000000000000000000000000000000001000000"
            "0000000000000000000000000000000000000000000000000000000000000009"
        )

        deposit_id_with = decode_query_data(query_data_with_prefix)
        deposit_id_without = decode_query_data(query_data_without_prefix)

        assert deposit_id_with == deposit_id_without == 9

    def test_decode_report_value_with_0x_prefix(self):
        """Test that function handles both with and without 0x prefix."""
        value_with_prefix = (
            "0x000000000000000000000000ae7cfe4cf579ec060f95d951bd5260a5a8c0dcdc"
            "000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000001b69b4bacd05f1500000000000000000000000000000000000000000000000000000000075bcd15000000000000000000000000000000000000000000000000000000000000002d74656c6c6f72317038386a7530796875746d6635703275373938787633756d616137756a77376763683972346600000000000000000000000000000000000000"
        )
        value_without_prefix = (
            "000000000000000000000000ae7cfe4cf579ec060f95d951bd5260a5a8c0dcdc"
            "000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000001b69b4bacd05f1500000000000000000000000000000000000000000000000000000000075bcd15000000000000000000000000000000000000000000000000000000000000002d74656c6c6f72317038386a7530796875746d6635703275373938787633756d616137756a77376763683972346600000000000000000000000000000000000000"
        )

        result_with = decode_report_value(value_with_prefix)
        result_without = decode_report_value(value_without_prefix)

        assert result_with == result_without
        assert result_with is not None

    @pytest.mark.asyncio
    async def test_get_trb_bridge_trusted_value(self):
        """Test getting TRBBridge trusted value. Get deposit 9 from palmito
        
        This test requires a valid RPC endpoint for Sepolia. Set ETHEREUM_RPC_URL
        environment variable to run this test (e.g., with an Infura or Alchemy API key).
        """
        import os
        
        # Skip test if no RPC URL is configured
        rpc_url = os.getenv("ETHEREUM_RPC_URL")
        if not rpc_url or "{" in rpc_url:  # Check for placeholder like {INFURA_API_KEY}
            pytest.skip("Test requires ETHEREUM_RPC_URL environment variable with valid RPC endpoint")
        
        query_data = (
            "0x0000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000008000"
            "0000000000000000000000000000000000000000000000000000000000095452424"
            "272696467650000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000004000000"
            "0000000000000000000000000000000000000000000000000000000000000001000000"
            "0000000000000000000000000000000000000000000000000000000000000009"
        )
        contract_address = "0x5acb5977f35b1A91C4fE0F4386eB669E046776F2"  # token bridge contract address on sepolia
        chain_id = 11155111  # sepolia
        
        result = await get_trb_bridge_trusted_value(query_data, contract_address, chain_id)
        assert result is not None
        
        #   [ deposits(uint256) method Response ]
        #   sender   address :  0x7660794eF8f978Ea0922DC29B3b534d93e1fc94A
        #   recipient   string :  tellor17gc67q05d5rgsz9caznm0s7s5eazwg2e3fkk8e
        #   amount   uint256 :  1000000000000000000
        #   tip   uint256 :  50000000000000000
        #   blockHeight   uint256 :  8015886
        assert result[0] == "0x7660794eF8f978Ea0922DC29B3b534d93e1fc94A".lower()
        assert result[1] == "tellor17gc67q05d5rgsz9caznm0s7s5eazwg2e3fkk8e"
        assert result[2] == 1000000000000000000
        assert result[3] == 50000000000000000
