# Final Arbiter Report

Repo: `layer-values-monitor`  
PR: `#33` - `TRBBridgeV2 report handling.`  
Branch: `trbbridgev2`  
Base: `upstream/main`

## Final Judgments

### BF-1

- **Bug Finder's claim (summary):** Stale-cache alerting can fire while the same cached value is still used as the trusted value for dispute logic.
- **Skeptic's counter (summary):** With `staleness_alert_multiplier >= 1`, a value that is still a TTL-valid cache hit cannot also exceed the staleness threshold; this is unreachable under default and example configs.
- **Your analysis:** `fetch_value_cached` only returns a cached row when `age < get_check_interval(...)`. Staleness uses `age > get_check_interval(...) * staleness_alert_multiplier`. The same `get_check_interval` base is used for both. If `staleness_alert_multiplier >= 1`, then staleness threshold is greater than or equal to TTL, so no age can satisfy both "valid hit" and "stale." The overlap would require `staleness_alert_multiplier < 1`, which is allowed by TOML but not documented or intended. Under the default value `3` and the example config, the Finder scenario does not occur.
- **VERDICT:** NOT A BUG
- **Confidence:** High

### BF-2

- **Bug Finder's claim (summary):** If an immediate refresh clears a dispute, the Discord alert still reflects only the first cached trusted value, not the fresh value that cleared the dispute.
- **Skeptic's counter (summary):** Accept - `immediate_refresh_value` is not surfaced in the message when the refresh clears the dispute.
- **Your analysis:** `perform_dispute_verification` sets `immediate_refresh_value` when the fresh fetch succeeds but returns early when `not immediate_disputable` without populating `second_trusted_value`. In `inspect`, the rich double-check message is only used when `second_trusted_value is not None`; otherwise the standard branch uses `trusted_value`, which is the original cached value passed into `inspect`. Operators therefore never see the refresh that canceled the dispute.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-3

- **Bug Finder's claim (summary):** `inspect_aggregate_report` resolves `query_type` but does not pass it into `fetch_value_cached`, so per-query TTL and staleness from config are ignored on that path.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `query_type` is set from `query.__class__.__name__`, but `fetch_value_cached(feed, query_id, logger)` is called without `query_type=...`, so `_get_ttl_for_query` falls back to `self._ttl` instead of per-query intervals.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-4

- **Bug Finder's claim (summary):** Deprecated-query handling sends one Discord alert per report in the batch, causing alert spam.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `for report in reports: deprecated_query_type_alert(...)` loops every report for the same deprecated-type batch.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-5

- **Bug Finder's claim (summary):** No per-key coalescing on cache miss, so concurrent misses can stampede the upstream API.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `fetch_value_cached` uses `get` and then, on miss, awaits `fetch_value` with no in-flight deduplication lock or future sharing.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-6

- **Bug Finder's claim (summary):** `TRBBRIDGE_CHAIN_ID` defaults to `1` in code while docs and example env use `11155111`.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `monitor.py` uses `int(os.getenv("TRBBRIDGE_CHAIN_ID", "1"))`; `env.example` and `README.md` document `11155111`. If the env var is omitted, behavior diverges from documented expectations.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-7

- **Bug Finder's claim (summary):** Renaming `config.toml.example` to `config_example.toml` breaks external scripts or docs.
- **Skeptic's counter (summary):** Disprove - no in-repo references to the old filename were found; breakage is only hypothetical outside the repo.
- **Your analysis:** No in-repo references to `config.toml.example` were found. Runtime still expects `config.toml`, which users create locally. Any external breakage would be outside this repository and is not a logic defect in the application itself.
- **VERDICT:** NOT A BUG
- **Confidence:** Medium

### BF-8

- **Bug Finder's claim (summary):** Percentage metric in `is_disputable` can divide by zero when `trusted_value == 0`.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `percent_diff = (reported_value - trusted_value) / trusted_value` has no guard when `trusted_value` is numeric zero.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-9

- **Bug Finder's claim (summary):** Config reload updates watcher cache settings, but `PriceCache._ttl` is only set at init, so code paths without `query_type` keep the old global TTL until restart.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `initialize_cache_with_config` sets `_price_cache._ttl` once; `watch_config` only calls `reload_config()` and does not refresh `_price_cache._ttl`. Paths that pass `query_type` use `ConfigWatcher.get_check_interval` live; paths that omit `query_type` use stale `_ttl`.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-10

- **Bug Finder's claim (summary):** Relaxing `telliot-feeds` to `>=0.4.15` is a bug because future installs may change behavior.
- **Skeptic's counter (summary):** Disprove - this is versioning risk, not a concrete application defect.
- **Your analysis:** This is dependency policy and reproducibility concern, not incorrect program logic at a point in time. It may be worth tracking as release hygiene, but not as an application bug.
- **VERDICT:** NOT A BUG
- **Confidence:** High

### BF-11

- **Bug Finder's claim (summary):** `PriceCache.get_stats` reads mutable counters and cache size without the async lock, so stats can be internally inconsistent.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `get_stats` is synchronous and does not use `self._lock` while other coroutines mutate `_hits`, `_misses`, and `_cache` under the lock.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-12

- **Bug Finder's claim (summary):** SpotPrice inspection double-counts cache stats by calling both `get` and `get_with_staleness`.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** A hit path runs `cache.get`, which increments hits, and then `get_with_staleness`, which increments hits again for the same entry.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-13

- **Bug Finder's claim (summary):** `--check-interval` help text is confusing because it cites `config.toml` while the committed example is `config_example.toml`.
- **Skeptic's counter (summary):** Accept - mildly confusing.
- **Your analysis:** The help string says "default: 180s from `config.toml`"; the example file is named `config_example.toml` with instructions to copy it to `config.toml`. Runtime path is `config.toml`, so the text is not wrong, but the naming mismatch can still confuse readers.
- **VERDICT:** REAL BUG
- **Confidence:** Medium

### BF-14

- **Bug Finder's claim (summary):** SpotPrice has staleness alerts but EVMCall does not, creating asymmetric stale-cache visibility.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `inspect_spotprice_path` calls `get_with_staleness` and `send_staleness_alert`; `inspect_evmcall_path` only uses `fetch_value_cached` with no staleness check or alert.
- **VERDICT:** REAL BUG
- **Confidence:** High

### BF-15

- **Bug Finder's claim (summary):** `inspect_aggregate_report` calls `get_query` twice redundantly.
- **Skeptic's counter (summary):** Accept.
- **Your analysis:** `inspect_aggregate_report` calls `get_query(query_data)` twice with the same `query_data` after an unnecessary second `None` check.
- **VERDICT:** REAL BUG
- **Confidence:** High

## Final Summary

- **Total bugs confirmed as real:** 12
- **Total bugs dismissed:** 3 (`BF-1`, `BF-7`, `BF-10`)

## Confirmed Bugs With Severity

- `BF-2`: Medium - misleading Discord context when refresh cancels dispute
- `BF-3`: Medium - wrong cache TTL behavior for aggregate inspection
- `BF-4`: Low-Medium - duplicate alert noise
- `BF-5`: Medium - thundering herd on upstream under concurrency
- `BF-6`: Medium - wrong default chain if env is unset
- `BF-8`: High - unhandled `ZeroDivisionError` on percentage metric
- `BF-9`: Low-Medium - stale global TTL after reload for paths without `query_type`
- `BF-11`: Low - stats can be inconsistent
- `BF-12`: Low - inflated cache hit and miss metrics
- `BF-13`: Low - CLI help text confusion
- `BF-14`: Low - observability gap for EVMCall stale cache
- `BF-15`: Low - redundant work and clarity issue

