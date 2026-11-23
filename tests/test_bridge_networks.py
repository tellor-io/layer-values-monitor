"""Built-in bridge contract defaults keyed by the Layer chain ID (bridge_networks)."""

import logging
import os
from unittest.mock import patch

from layer_values_monitor import bridge_networks
from layer_values_monitor.bridge_networks import (
    _MAINNET_BRIDGE,
    _SEPOLIA_BRIDGE_V1,
    _SEPOLIA_BRIDGE_V2,
    _configured_bridge_rpc_urls,
    resolve_bridge_chain_id,
    resolve_contract_address,
    validate_bridge_rpc,
)

import pytest

MAINNET = "tellor-1"
SEPOLIA = "11155111"


@pytest.fixture(autouse=True)
def clean_bridge_env(monkeypatch):
    """Deterministic resolution: no env overrides, no Layer chain, no once-log cache."""
    for name in (
        "CHAIN_ID",
        "TRBBRIDGE_CONTRACT_ADDRESS",
        "TRBBRIDGEV2_CONTRACT_ADDRESS",
        "TRBBRIDGE_CHAIN_ID",
        "INFURA_API_KEY",
        "EVM_RPC_URLS",
        "EVM_RPC_URLS_1",
        "EVM_RPC_URLS_11155111",
    ):
        monkeypatch.delenv(name, raising=False)
    bridge_networks._announced.clear()


class TestContractAddressDefaults:
    def test_tellor1_resolves_both_to_mainnet_bridge(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        assert resolve_contract_address("TRBBRIDGE_CONTRACT_ADDRESS") == _MAINNET_BRIDGE
        assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") == _MAINNET_BRIDGE

    def test_layertest5_resolves_sepolia_pair(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "layertest-5")
        assert resolve_contract_address("TRBBRIDGE_CONTRACT_ADDRESS") == _SEPOLIA_BRIDGE_V1
        assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") == _SEPOLIA_BRIDGE_V2

    def test_layertest5_match_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "LayerTest-5")
        assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") == _SEPOLIA_BRIDGE_V2

    def test_env_override_wins_over_builtin(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("TRBBRIDGEV2_CONTRACT_ADDRESS", "0x1111111111111111111111111111111111111111")
        assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") == "0x1111111111111111111111111111111111111111"

    @pytest.mark.parametrize("layer_chain", ["layer-1", "layertest-8", "layertest-8-lvm-test"])
    def test_other_chains_without_env_return_none(self, monkeypatch, layer_chain):
        # Exact-match rule: only layertest-5 owns the Sepolia pair; other testnets must set env vars.
        monkeypatch.setenv("CHAIN_ID", layer_chain)
        assert resolve_contract_address("TRBBRIDGE_CONTRACT_ADDRESS") is None
        assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") is None

    def test_no_layer_chain_returns_none(self):
        # Pre-existing behavior: unset env var with no Layer chain hint stays an error path.
        assert resolve_contract_address("TRBBRIDGE_CONTRACT_ADDRESS") is None

    def test_prefix_rule_does_not_swallow_unrelated_chains(self, monkeypatch):
        # "layer-1" (local devnet) must NOT inherit the layertest-5 Sepolia defaults.
        monkeypatch.setenv("CHAIN_ID", "layer-1")
        assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") is None

    def test_layertest8_does_not_inherit_layertest5_defaults(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "layertest-8")
        assert resolve_bridge_chain_id() == 1  # historical fallback, not Sepolia


class TestEvmChainIdDefaults:
    def test_tellor1_defaults_to_mainnet(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        assert resolve_bridge_chain_id() == 1

    def test_layertest_defaults_to_sepolia(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "layertest-5")
        assert resolve_bridge_chain_id() == 11155111

    def test_env_override_wins(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "layertest-5")
        monkeypatch.setenv("TRBBRIDGE_CHAIN_ID", "1")
        assert resolve_bridge_chain_id() == 1

    def test_unknown_chain_falls_back_to_historical_default(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "layer-1")
        assert resolve_bridge_chain_id() == 1

    def test_no_layer_chain_falls_back_to_historical_default(self):
        assert resolve_bridge_chain_id() == 1


class TestPlainEvmRpcUrls:
    """Plain EVM_RPC_URLS is a fallback for the chain-suffixed var (coupled via CHAIN_ID)."""

    def test_plain_evm_rpc_urls_used_when_suffix_absent(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", "layertest-5")
        monkeypatch.setenv("EVM_RPC_URLS", "https://sep1.example,https://sep2.example")
        assert _configured_bridge_rpc_urls(11155111) == ["https://sep1.example", "https://sep2.example"]

    def test_suffixed_evm_rpc_urls_take_precedence(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("EVM_RPC_URLS", "https://wrong-chain-default")
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://right-chain-specific")
        assert _configured_bridge_rpc_urls(1) == ["https://right-chain-specific"]

    def test_plain_urls_gate_fires_on_wrong_chain(self, monkeypatch):
        """Startup gate must probe plain-var URLs, not just suffixed ones."""
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("EVM_RPC_URLS", "https://rpc.example")
        probes = TestValidateBridgeRpc.probe({"https://rpc.example": 11155111})
        with patch("layer_values_monitor.bridge_networks.validate_rpc_connection", probes):
            with pytest.raises(ValueError, match="reports chain ID 11155111"):
                validate_bridge_rpc()


class TestLogOnce:
    def test_default_is_announced_only_once_per_process(self, monkeypatch, caplog):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        import logging

        logger = logging.getLogger("test-bridge-networks")
        with caplog.at_level(logging.INFO, logger="test-bridge-networks"):
            resolve_contract_address("TRBBRIDGE_CONTRACT_ADDRESS", logger=logger)
            resolve_contract_address("TRBBRIDGE_CONTRACT_ADDRESS", logger=logger)
        assert sum("built-in default" in r.message for r in caplog.records) == 1

    def test_unknown_env_var_returns_none_even_on_known_chain(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        assert resolve_contract_address("SOME_OTHER_ENV") is None


def test_announced_cache_does_not_leak_across_layer_chains(monkeypatch):
    monkeypatch.setenv("CHAIN_ID", MAINNET)
    assert os.getenv("TRBBRIDGEV2_CONTRACT_ADDRESS") is None
    assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") == _MAINNET_BRIDGE
    monkeypatch.setenv("CHAIN_ID", "layertest-5")
    assert resolve_contract_address("TRBBRIDGEV2_CONTRACT_ADDRESS") == _SEPOLIA_BRIDGE_V2


class TestValidateBridgeRpc:
    """Startup gate: wrong-chain RPC is fatal, transient outage is not (validate_bridge_rpc)."""

    @staticmethod
    def probe(url_map):
        """Fake validate_rpc_connection: (True, "", chain_id) per URL, or (False, "down", None)."""

        def _fake(url, name, logger_instance):
            result = url_map[url]
            return (True, "", result) if isinstance(result, int) else (False, "down", None)

        return _fake

    def test_mismatch_is_fatal(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://rpc.example")
        probes = self.probe({"https://rpc.example": 11155111})
        with patch("layer_values_monitor.bridge_networks.validate_rpc_connection", probes):
            with pytest.raises(ValueError, match="reports chain ID 11155111"):
                validate_bridge_rpc()

    def test_match_passes(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://rpc.example")
        probes = self.probe({"https://rpc.example": 1})
        with patch("layer_values_monitor.bridge_networks.validate_rpc_connection", probes):
            validate_bridge_rpc()  # no raise

    def test_partial_mismatch_is_fatal_and_names_the_url(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://good,https://bad")
        probes = self.probe({"https://good": 1, "https://bad": 137})
        with patch("layer_values_monitor.bridge_networks.validate_rpc_connection", probes):
            with pytest.raises(ValueError, match=r"https://bad reports chain ID 137"):
                validate_bridge_rpc()

    def test_unreachable_endpoint_only_warns(self, monkeypatch, caplog):
        """A startup RPC outage must not stop the whole monitor, unlike a mismatch."""
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://down.example")
        probes = self.probe({"https://down.example": None})
        logger = logging.getLogger("test-validate-rpc")
        with caplog.at_level(logging.WARNING, logger="test-validate-rpc"):
            with patch("layer_values_monitor.bridge_networks.validate_rpc_connection", probes):
                validate_bridge_rpc(logger=logger)  # no raise
        assert any("continuing; runtime retries" in r.message for r in caplog.records)

    def test_no_urls_configured_only_warns(self, monkeypatch, caplog):
        """No EVM_RPC_URLS / INFURA: runtime falls back to TelliotConfig, so warn instead of die."""
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        logger = logging.getLogger("test-validate-rpc-nourls")
        with caplog.at_level(logging.WARNING, logger="test-validate-rpc-nourls"):
            validate_bridge_rpc(logger=logger)  # no raise, no network probe
        assert any("TelliotConfig" in r.message for r in caplog.records)

    def test_infura_key_counts_as_configured_url(self, monkeypatch):
        monkeypatch.setenv("CHAIN_ID", MAINNET)
        monkeypatch.setenv("INFURA_API_KEY", "k")
        probes = self.probe({"https://mainnet.infura.io/v3/k": 11155111})
        with patch("layer_values_monitor.bridge_networks.validate_rpc_connection", probes):
            with pytest.raises(ValueError, match="mainnet.infura.io"):
                validate_bridge_rpc()
