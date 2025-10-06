"""Test Discord alert message formatting for different report types."""


from layer_values_monitor.discord import build_alert_message, format_difference, format_values
from layer_values_monitor.telliot_feeds import extract_query_info


class MockQuery:
    """Mock query object for testing."""

    def __init__(self, asset=None, currency=None, query_type=None):
        if asset:
            self.asset = asset
        if currency:
            self.currency = currency
        if query_type:
            self.type = query_type


def test_format_difference_percentage():
    """Test percentage difference formatting."""
    assert format_difference(0.0896, "percentage") == "8.96%"
    assert format_difference(0.1001, "percentage") == "10.01%"
    assert format_difference(0.05, "percentage") == "5.00%"
    assert format_difference(0.25, "PeRcEnTaGe") == "25.00%"  # Case insensitive


def test_format_difference_range():
    """Test range difference formatting."""
    assert format_difference(1.5432, "range") == "1.5432"
    assert format_difference(0.0001, "range") == "0.0001"
    assert format_difference(100.9999, "RANGE") == "100.9999"  # Case insensitive


def test_format_difference_equality():
    """Test equality difference formatting."""
    assert format_difference(1.0, "equality") == "1.0"
    assert format_difference(0.0, "equality") == "0.0"


def test_format_values_simple():
    """Test formatting of simple numeric values."""
    result = format_values(7.44, 6.827876242343322)
    assert result == "**Reported:** 7.44\n**Trusted:** 6.827876242343322"


def test_format_values_dict():
    """Test formatting of dict values (TRBBridge)."""
    reported = {
        "eth_address": "0x1a2b3c4d5e6f7890abcdef1234567890abcdef12",
        "layer_address": "layer1xyz123abc456def789",
        "amount": 1000000000000000000,
        "tip": 0,
    }
    trusted = {
        "eth_address": "0x1a2b3c4d5e6f7890abcdef1234567890abcdef12",
        "layer_address": "layer1xyz123abc456def789",
        "amount": 2000000000000000000,
        "tip": 0,
    }
    result = format_values(reported, trusted)
    
    assert "**Reported:**" in result
    assert "**Trusted:**" in result
    assert "eth_address: 0x1a2b3c4d5e6f7890abcdef1234567890abcdef12" in result
    assert "amount: 1000000000000000000" in result
    assert "amount: 2000000000000000000" in result


def test_extract_query_info_spot_price():
    """Test extracting asset pair from SpotPrice query."""
    query = MockQuery(asset="BTC", currency="USD")
    assert extract_query_info(query) == "BTC/USD"
    
    query = MockQuery(asset="ETH", currency="USD")
    assert extract_query_info(query) == "ETH/USD"
    
    query = MockQuery(asset="SAGA", currency="USD")
    assert extract_query_info(query) == "SAGA/USD"


def test_extract_query_info_none_with_type():
    """Test extracting query info when query is None but query_type is provided."""
    assert extract_query_info(None, query_type="EVMCall") == "EVMCall"
    assert extract_query_info(None, query_type="TRBBridge") == "TRBBridge"


def test_extract_query_info_none_without_type():
    """Test extracting query info when both query and query_type are None."""
    assert extract_query_info(None, query_type=None) == "Unknown"
    assert extract_query_info(None) == "Unknown"


def test_build_alert_message_spot_price():
    """Test building alert message for SpotPrice query."""
    msg = build_alert_message(
        query_info="SAGA/USD",
        value_display="**Reported:** 7.44\n**Trusted:** 6.827876242343322",
        diff_str="8.96%",
        reporter="layer1abcdefghijklmnopqrstuvwxyz123456",
        power="1000",
        tx_hash="CC0CD8EB401B4FCBCC77A67DAD43BF886FFD301B87B58C1782459B814C2BFA07",
    )
    
    print("\n" + "="*60)
    print("SPOT PRICE ALERT (SAGA/USD):")
    print("="*60)
    print(msg)
    print("="*60)
    
    assert "**Asset:** SAGA/USD" in msg
    assert "**Reported:** 7.44" in msg
    assert "**Trusted:** 6.827876242343322" in msg
    assert "**Difference:** 8.96%" in msg
    assert "layer1ab...123456" in msg  # First 8 chars + last 6 chars
    assert "**Power:** 1000" in msg
    assert "CC0CD8EB401B4FCBCC77A67DAD43BF886FFD301B87B58C1782459B814C2BFA07" in msg


def test_build_alert_message_btc_usd():
    """Test building alert message for BTC/USD."""
    msg = build_alert_message(
        query_info="BTC/USD",
        value_display="**Reported:** 67500.00\n**Trusted:** 64285.71",
        diff_str="5.00%",
        reporter="layer1qwertyuiopasdfghjklzxcvbnm987654",
        power="5000",
        tx_hash="1F2E3D4C5B6A7980FEDC89BA7654321098765432ABCDEF1234567890ABCDEF12",
    )
    
    print("\n" + "="*60)
    print("SPOT PRICE ALERT (BTC/USD):")
    print("="*60)
    print(msg)
    print("="*60)
    
    assert "**Asset:** BTC/USD" in msg
    assert "**Reported:** 67500.00" in msg
    assert "**Trusted:** 64285.71" in msg
    assert "**Difference:** 5.00%" in msg


def test_build_alert_message_evmcall():
    """Test building alert message for EVMCall query."""
    msg = build_alert_message(
        query_info="EVMCall",
        value_display=(
            "**Reported:** 0x00000000000000000000000000000000000000000000000000000000000f4240\n"
            "**Trusted:** 0x00000000000000000000000000000000000000000000000000000000000f4241"
        ),
        diff_str="1.0",
        reporter="layer1mnopqrstuvwxyz123456789abcdefghi",
        power="2500",
        tx_hash="DEF456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234",
    )
    
    print("\n" + "="*60)
    print("EVMCALL ALERT:")
    print("="*60)
    print(msg)
    print("="*60)
    
    assert "**Asset:** EVMCall" in msg
    assert "0x00000000000000000000000000000000000000000000000000000000000f4240" in msg
    assert "**Difference:** 1.0" in msg


def test_build_alert_message_trbbridge():
    """Test building alert message for TRBBridge query."""
    reported_display = (
        "  - eth_address: 0x1a2b3c4d5e6f7890abcdef1234567890abcdef12\n"
        "  - layer_address: layer1xyz123abc456def789\n"
        "  - amount: 1000000000000000000\n"
        "  - tip: 0"
    )
    trusted_display = (
        "  - eth_address: 0x1a2b3c4d5e6f7890abcdef1234567890abcdef12\n"
        "  - layer_address: layer1xyz123abc456def789\n"
        "  - amount: 2000000000000000000\n"
        "  - tip: 0"
    )
    value_display = f"**Reported:**\n{reported_display}\n**Trusted:**\n{trusted_display}"
    
    msg = build_alert_message(
        query_info="TRBBridge",
        value_display=value_display,
        diff_str="1.0",
        reporter="layer1zxcvbnmasdfghjklqwertyuiop123456",
        power="3000",
        tx_hash="ABC123456789DEF123456789ABC123456789DEF123456789ABC123456789DEF12",
    )
    
    print("\n" + "="*60)
    print("TRBBRIDGE ALERT:")
    print("="*60)
    print(msg)
    print("="*60)
    
    assert "**Asset:** TRBBridge" in msg
    assert "**Reported:**" in msg
    assert "**Trusted:**" in msg
    assert "eth_address: 0x1a2b3c4d5e6f7890abcdef1234567890abcdef12" in msg
    assert "amount: 1000000000000000000" in msg
    assert "amount: 2000000000000000000" in msg
    assert "**Difference:** 1.0" in msg


def test_build_alert_message_short_reporter():
    """Test that short reporter addresses aren't truncated."""
    msg = build_alert_message(
        query_info="ETH/USD",
        value_display="**Reported:** 3850.50\n**Trusted:** 3500.00",
        diff_str="10.01%",
        reporter="layer1short",
        power="100",
        tx_hash="ABC123",
    )
    
    # Short addresses should not be truncated
    assert "layer1short" in msg


def test_complete_workflow_spot_price():
    """Test complete workflow for spot price alert."""
    # Simulate SAGA/USD alertable value
    query = MockQuery(asset="SAGA", currency="USD")
    query_info = extract_query_info(query, query_type="SpotPrice")
    
    reported = 7.44
    trusted = 6.827876242343322
    diff = 0.0896
    
    diff_str = format_difference(diff, "percentage")
    value_display = format_values(reported, trusted)
    
    msg = build_alert_message(
        query_info=query_info,
        value_display=value_display,
        diff_str=diff_str,
        reporter="layer1abcdefghijklmnopqrstuvwxyz123456",
        power="1000",
        tx_hash="CC0CD8EB401B4FCBCC77A67DAD43BF886FFD301B87B58C1782459B814C2BFA07",
    )
    
    print("\n" + "="*60)
    print("COMPLETE WORKFLOW - SPOT PRICE:")
    print("="*60)
    print(msg)
    print("="*60)
    
    assert query_info == "SAGA/USD"
    assert diff_str == "8.96%"
    assert "SAGA/USD" in msg
    assert "7.44" in msg
    assert "6.827876242343322" in msg
    assert "8.96%" in msg


def test_complete_workflow_trbbridge():
    """Test complete workflow for TRBBridge alert."""
    query_info = extract_query_info(None, query_type="TRBBridge")
    
    reported = {
        "eth_address": "0x1a2b3c4d5e6f7890abcdef1234567890abcdef12",
        "layer_address": "layer1xyz123abc456def789",
        "amount": 1000000000000000000,
        "tip": 0,
    }
    trusted = {
        "eth_address": "0x1a2b3c4d5e6f7890abcdef1234567890abcdef12",
        "layer_address": "layer1xyz123abc456def789",
        "amount": 2000000000000000000,
        "tip": 0,
    }
    diff = 1.0
    
    diff_str = format_difference(diff, "equality")
    value_display = format_values(reported, trusted)
    
    msg = build_alert_message(
        query_info=query_info,
        value_display=value_display,
        diff_str=diff_str,
        reporter="layer1trbbridge123456789abcdefghijklmn",
        power="3000",
        tx_hash="TRBBRIDGE123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789",
    )
    
    print("\n" + "="*60)
    print("COMPLETE WORKFLOW - TRBBRIDGE:")
    print("="*60)
    print(msg)
    print("="*60)
    
    assert query_info == "TRBBridge"
    assert diff_str == "1.0"
    assert "TRBBridge" in msg
    assert "amount: 1000000000000000000" in msg
    assert "amount: 2000000000000000000" in msg

