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
        return EC_STATE["chain_by_url"].get(self._url, EC_STATE["chain_id"])


class FakeWeb3:
    def __init__(self, provider):
        self.provider = provider
        self.eth = FakeEth(provider)

    @staticmethod
    def HTTPProvider(url):  # noqa: N802 - mirrors web3's API name
        return url


EC_STATE = {"fail": set(), "chain_id": 1, "chain_by_url": {}}


@pytest.fixture(autouse=True)
def fake_web3(monkeypatch):
    EC_STATE["fail"] = set()
    EC_STATE["chain_id"] = 1
    EC_STATE["chain_by_url"] = {}
    monkeypatch.setattr(ec, "Web3", FakeWeb3)
    # A developer's .env leaks in via conftest's load_dotenv — URL resolution must be deterministic.
    for name in ("EVM_RPC_URLS", "EVM_RPC_URLS_1", "EVM_RPC_URLS_11155111", "INFURA_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    ec.clear_cache()
    yield
    ec.clear_cache()


@pytest.fixture
def url_list(monkeypatch):
    monkeypatch.setenv("EVM_RPC_URLS_1", "https://p.example,https://s.example,https://t.example")


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

    def test_wrong_chain_is_skipped_for_the_next_url(self, monkeypatch):
        """A chain-id mismatch is not cached and is not returned; the next URL is used."""
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://wrong.example,https://right.example")
        EC_STATE["chain_by_url"]["https://wrong.example"] = 11155111
        w3 = ec.get_web3_connection(1)
        assert w3 is not None
        assert w3.provider == "https://right.example"
        assert ec.get_cached_chain_ids() == [1]
        assert ec.get_web3_connection(1) is w3


class TestPlainEvmRpcUrls:
    """get_web3_connection falls back to plain EVM_RPC_URLS when EVM_RPC_URLS_<chain> is unset."""

    def test_plain_urls_used_when_suffix_absent(self, monkeypatch):
        monkeypatch.setenv("EVM_RPC_URLS", "https://plain1.example,https://plain2.example")
        w3 = ec.get_web3_connection(1)
        assert w3 is not None
        assert w3.provider == "https://plain1.example"

    def test_suffixed_urls_take_precedence_over_plain(self, monkeypatch):
        monkeypatch.setenv("EVM_RPC_URLS", "https://wrong-chain-default.example")
        monkeypatch.setenv("EVM_RPC_URLS_1", "https://right-chain-specific.example")
        w3 = ec.get_web3_connection(1)
        assert w3 is not None
        assert w3.provider == "https://right-chain-specific.example"
