"""Tests for the hardened deposits() fetch (retry, sanity, anchor fallback)."""

from unittest.mock import MagicMock

from layer_values_monitor.trb_bridge import ZERO_ADDRESS, fetch_deposit, is_zero_struct

import pytest

CONTRACT = "0x62733e63499a25E35844c91275d4c3bdb159D29d"
REAL = ("0x7660794ef8f978ea0922dc29b3b534d93e1fc94a", "tellor1abc", 1000, 50)  # fetch lowercases sender


def make_w3(call_side_effect):
    """Fake Web3 whose deposits(id).call() uses the given side_effect."""
    fn = MagicMock()
    fn.call.side_effect = call_side_effect
    w3 = MagicMock()
    w3.eth.contract.return_value.functions.deposits.return_value = fn
    return w3, fn


async def instant_sleep(_seconds):
    return None


@pytest.mark.asyncio
async def test_fetch_retries_then_succeeds():
    """First-attempt exception then success: retry works, backoff applied between attempts."""
    slept = []

    async def spy_sleep(seconds):
        slept.append(seconds)

    w3, fn = make_w3([Exception("connection reset"), (*REAL, 8015886)])
    deposit, kind = await fetch_deposit(
        lambda attempt: w3, CONTRACT, 9, max_attempts=3, sleep=spy_sleep, logger=MagicMock()
    )
    assert kind == "ok"
    assert deposit == REAL
    assert fn.call.call_count == 2
    assert slept == [2.0]  # backoff between attempt 1 and 2


@pytest.mark.asyncio
async def test_fetch_zero_struct_is_not_a_trusted_value():
    """The all-zeros mapping default must return 'zero_struct', never a tuple (G4)."""
    w3, fn = make_w3([(ZERO_ADDRESS, "", 0, 0, 0)])
    deposit, kind = await fetch_deposit(lambda attempt: w3, CONTRACT, 9, sleep=instant_sleep, logger=MagicMock())
    assert deposit is None
    assert kind == "zero_struct"
    assert fn.call.call_count == 1  # sanity answer is definitive: no retry storm


@pytest.mark.asyncio
async def test_fetch_finalized_rejected_falls_back_to_latest():
    """An anchor rejection gets one un-anchored retry inside the same attempt (G5 trap)."""

    def call_side_effect(*args, **kwargs):
        if "block_identifier" in kwargs:
            raise Exception("unknown block tag: finalized")
        return (*REAL, 8015886)

    w3, fn = make_w3(call_side_effect)
    deposit, kind = await fetch_deposit(
        lambda attempt: w3, CONTRACT, 9, anchor="finalized", sleep=instant_sleep, logger=MagicMock()
    )
    assert kind == "ok"
    assert deposit == REAL
    assert fn.call.call_count == 2
    fn.call.assert_any_call(block_identifier="finalized")
    fn.call.assert_any_call()


@pytest.mark.asyncio
async def test_fetch_all_attempts_fail_returns_rpc_error():
    """A dead provider across all attempts yields rpc_error with bounded backoff."""
    slept = []

    async def spy_sleep(seconds):
        slept.append(seconds)

    w3, fn = make_w3([Exception("down")] * 3)
    deposit, kind = await fetch_deposit(lambda attempt: w3, CONTRACT, 9, max_attempts=3, sleep=spy_sleep, logger=MagicMock())
    assert deposit is None
    assert kind == "rpc_error"
    assert fn.call.call_count == 3
    assert slept == [2.0, 6.0]


@pytest.mark.asyncio
async def test_fetch_provider_builder_none_counts_as_rpc_error():
    deposit, kind = await fetch_deposit(lambda attempt: None, CONTRACT, 9, sleep=instant_sleep, logger=MagicMock())
    assert (deposit, kind) == (None, "rpc_error")


@pytest.mark.asyncio
async def test_fetch_provider_builder_rotates_per_attempt():
    """provider_builder must be invoked with the attempt index so callers can fail over."""
    seen = []

    def builder(attempt):
        seen.append(attempt)
        if attempt == 0:
            raise Exception("dead primary")
        w3, _ = make_w3([(*REAL, 8015886)])
        return w3

    deposit, kind = await fetch_deposit(builder, CONTRACT, 9, sleep=instant_sleep, logger=MagicMock())
    assert kind == "ok"
    assert seen == [0, 1]


def test_is_zero_struct():
    assert is_zero_struct((ZERO_ADDRESS, "", 0, 0, 0)) is True
    assert is_zero_struct((ZERO_ADDRESS.upper(), "", 0, 0, 0)) is True  # mixed case accepted
    assert is_zero_struct((*REAL, 8015886)) is False
    assert is_zero_struct((ZERO_ADDRESS, "", 0, 0, 1)) is False  # blockNumber set = not default
