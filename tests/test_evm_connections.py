"""Tests for RPC connection rotation, invalidation, and the secondary provider."""

import layer_values_monitor.evm_connections as ec

import pytest


class FakeEth:
    def __init__(self, url):
        self._url = url

    @property
    def block_number(self):
        if self._url in EC_STATE["fail"]:
            raise ConnectionError(f"{self._url} down")
        return 42

    @property
    def chain_id(self):
        return EC_STATE["chain_id"]


class FakeWeb3:
    def __init__(self, provider):
        self.provider = provider
        self.eth = FakeEth(provider)

    @staticmethod
    def HTTPProvider(url):  # noqa: N802 - mirrors web3's API name
        return url


EC_STATE = {"fail": set(), "chain_id": 1}


@pytest.fixture(autouse=True)
def fake_web3(monkeypatch):
    EC_STATE["fail"] = set()
    EC_STATE["chain_id"] = 1
    monkeypatch.setattr(ec, "Web3", FakeWeb3)
    ec.clear_cache()
    yield
    ec.clear_cache()


@pytest.fixture
def url_list(monkeypatch):
    monkeypatch.setenv("EVM_RPC_URLS_1", "https://p.example,https://s.example,https://t.example")
    monkeypatch.delenv("BRIDGE_SECONDARY_RPC_URL", raising=False)


class TestAttemptRotation:
    def test_attempt_zero_uses_cache(self, url_list):
        w3a = ec.get_web3_connection(1)
        assert w3a.provider == "https://p.example"
        w3b = ec.get_web3_connection(1)
        assert w3b is w3a  # cached, no rebuild

    def test_attempt_positive_skips_cache_and_rotates(self, url_list):
        ec.get_web3_connection(1)  # primary p cached
        w3 = ec.get_web3_connection(1, attempt=1)
        assert w3.provider == "https://s.example"  # rotation starts at index 1

        w3 = ec.get_web3_connection(1, attempt=2)
        assert w3.provider == "https://t.example"

    def test_dead_primary_fails_over_per_attempt(self, url_list):
        """The G3 latch fix: a dead primary must not stick across attempts."""
        EC_STATE["fail"].add("https://p.example")
        w3 = ec.get_web3_connection(1, attempt=1)
        assert w3.provider == "https://s.example"

    def test_invalidate_drops_cache(self, url_list):
        ec.get_web3_connection(1)
        assert ec.get_cached_chain_ids() == [1]
        ec.invalidate_web3_connection(1)
        assert ec.get_cached_chain_ids() == []
        # Rebuild happens on next attempt=0 call
        w3 = ec.get_web3_connection(1)
        assert w3.provider == "https://p.example"

    def test_invalidate_unknown_chain_is_noop(self, url_list):
        ec.invalidate_web3_connection(999)


class TestSecondaryConnection:
    def test_explicit_secondary_env(self, url_list, monkeypatch):
        monkeypatch.setenv("BRIDGE_SECONDARY_RPC_URL", "https://explicit-secondary.example")
        w3 = ec.get_secondary_connection(1)
        assert w3.provider == "https://explicit-secondary.example"

    def test_secondary_fails_returns_none(self, url_list, monkeypatch):
        EC_STATE["fail"].add("https://explicit-secondary.example")
        monkeypatch.setenv("BRIDGE_SECONDARY_RPC_URL", "https://explicit-secondary.example")
        assert ec.get_secondary_connection(1) is None

    def test_secondary_rotates_away_from_cached_primary(self, url_list):
        ec.get_web3_connection(1)  # caches p as the primary source
        w3 = ec.get_secondary_connection(1)
        assert w3.provider == "https://s.example"  # first entry distinct from p

    def test_secondary_rotates_when_primary_is_backup(self, url_list):
        EC_STATE["fail"].add("https://p.example")
        ec.get_web3_connection(1)  # primary dead → s cached as the source
        EC_STATE["fail"].discard("https://p.example")  # provider recovered, but cache source stays s
        w3 = ec.get_secondary_connection(1)
        assert w3.provider == "https://p.example"  # distinct from cached source

    def test_secondary_none_without_url_list(self, monkeypatch):
        monkeypatch.delenv("EVM_RPC_URLS_1", raising=False)
        monkeypatch.delenv("BRIDGE_SECONDARY_RPC_URL", raising=False)
        assert ec.get_secondary_connection(1) is None

    def test_secondary_none_when_only_primary_exists(self, monkeypatch):
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://only.example")
        ec.get_web3_connection(1)
        assert ec.get_secondary_connection(1) is None
