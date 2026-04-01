# Bug Skeptic Report

Repo: `layer-values-monitor`  
PR: `#33` - `TRBBridgeV2 report handling.`  
Branch: `trbbridgev2`  
Base: `upstream/main`

## Review

### BF-1 - original score: 10
- **Counter-argument:** Staleness uses `ConfigWatcher.get_staleness_threshold` = `get_check_interval(...) * staleness_alert_multiplier`, while cache validity in `PriceCache.get` uses the same `get_check_interval` as TTL. For any `staleness_alert_multiplier >= 1`, staleness threshold is greater than or equal to TTL, so if `cache.get` returns a hit, `get_with_staleness` cannot report `is_stale` for that same entry. The scenario only appears if an operator sets `staleness_alert_multiplier < 1`, which is not documented as supported.
- **Confidence:** 82%
- **Decision:** DISPROVE
- **Points gained/risked:** +10

### BF-2 - original score: 5
- **Counter-argument:** `perform_dispute_verification` sets `immediate_refresh_value` but never maps it to `second_trusted_value`; `second_trusted_value` is only set from the final fetch after the 10-second wait. On the early return when the immediate refresh clears the dispute, `second_trusted_value` remains `None`, and the Discord branch falls back to formatting the alert with the original cached `trusted_value`.
- **Confidence:** 92%
- **Decision:** ACCEPT
- **Points gained/risked:** -5 (risked if dismissed: -10)

### BF-3 - original score: 5
- **Counter-argument:** `inspect_aggregate_report` resolves `query_type` but calls `fetch_value_cached(feed, query_id, logger)` without passing it, so `_get_ttl_for_query` falls back to `self._ttl` instead of per-query `ConfigWatcher.get_check_interval`.
- **Confidence:** 95%
- **Decision:** ACCEPT
- **Points gained/risked:** -5

### BF-4 - original score: 5
- **Counter-argument:** The deprecated path explicitly loops `for report in reports` and calls `deprecated_query_type_alert` per report.
- **Confidence:** 95%
- **Decision:** ACCEPT
- **Points gained/risked:** -5

### BF-5 - original score: 5
- **Counter-argument:** `fetch_value_cached` only uses `cache.get`, then on miss awaits `fetch_value` with no per-`query_id` mutex or single-flight logic. Concurrent coroutines can all miss and call `fetch_value` together.
- **Confidence:** 88%
- **Decision:** ACCEPT
- **Points gained/risked:** -5

### BF-6 - original score: 5
- **Counter-argument:** Code uses `int(os.getenv("TRBBRIDGE_CHAIN_ID", "1"))`. `README.md` and `env.example` both show `11155111`. The default in code is therefore inconsistent with the documented setup.
- **Confidence:** 95%
- **Decision:** ACCEPT
- **Points gained/risked:** -5

### BF-7 - original score: 5
- **Counter-argument:** The repo contains `config_example.toml` and no in-repo references to `config.toml.example` were found. This looks like a possible external migration issue, not a demonstrated breakage inside this repository.
- **Confidence:** 80%
- **Decision:** DISPROVE
- **Points gained/risked:** +5

### BF-8 - original score: 5
- **Counter-argument:** `is_disputable` guards `trusted_value is None` only. For `metric == "percentage"` it computes `(reported_value - trusted_value) / trusted_value`, which divides by zero if `trusted_value == 0`.
- **Confidence:** 93%
- **Decision:** ACCEPT
- **Points gained/risked:** -5

### BF-9 - original score: 5
- **Counter-argument:** `initialize_cache_with_config` sets `_price_cache._ttl` once from `config_watcher.get_check_interval()`. `reload_config` updates `cache_settings` on the watcher, but nothing updates `_price_cache._ttl` afterward. For calls without `query_type`, TTL falls back to that stale `_ttl`, which matches aggregate behavior in BF-3.
- **Confidence:** 90%
- **Decision:** ACCEPT
- **Points gained/risked:** -5

### BF-10 - original score: 1
- **Counter-argument:** This is dependency-policy or supply-chain risk, not a defect in application logic. `uv.lock` pins the resolved version for locked installs.
- **Confidence:** 85%
- **Decision:** DISPROVE
- **Points gained/risked:** +1

### BF-11 - original score: 1
- **Counter-argument:** `get_stats` reads `_hits`, `_misses`, and `len(self._cache)` without `async with self._lock`, unlike the mutating paths.
- **Confidence:** 90%
- **Decision:** ACCEPT
- **Points gained/risked:** -1

### BF-12 - original score: 1
- **Counter-argument:** `inspect_spotprice_path` calls `fetch_value_cached` (which calls `cache.get` and counts a hit on success) and then `get_with_staleness` (which increments `_hits` again for the same existing entry).
- **Confidence:** 92%
- **Decision:** ACCEPT
- **Points gained/risked:** -1

### BF-13 - original score: 1
- **Counter-argument:** `main.py` help still says the default is from `config.toml` while the checked-in template is `config_example.toml`; the wording is easy to misread.
- **Confidence:** 78%
- **Decision:** ACCEPT
- **Points gained/risked:** -1

### BF-14 - original score: 1
- **Counter-argument:** `inspect_spotprice_path` runs staleness alerting, while `inspect_evmcall_path` fetches via cache but has no analogous `get_with_staleness` or `send_staleness_alert` block. This is an observability asymmetry rather than an incorrect comparison claim.
- **Confidence:** 88%
- **Decision:** ACCEPT
- **Points gained/risked:** -1

### BF-15 - original score: 1
- **Counter-argument:** `get_query(query_data)` is called twice in `inspect_aggregate_report` with the same `query_data`.
- **Confidence:** 98%
- **Decision:** ACCEPT
- **Points gained/risked:** -1

## Summary

- **Total bugs disproved:** 3 (`BF-1`, `BF-7`, `BF-10`)
- **Total bugs accepted as real:** 12
- **Final score:** `-29`

## Verified Bug List

`BF-2`, `BF-3`, `BF-4`, `BF-5`, `BF-6`, `BF-8`, `BF-9`, `BF-11`, `BF-12`, `BF-13`, `BF-14`, `BF-15`
