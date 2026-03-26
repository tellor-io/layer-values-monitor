# Bug Finder Report

Repo: `layer-values-monitor`  
PR: `#33` - `TRBBridgeV2 report handling.`  
Branch: `trbbridgev2`  
Base: `upstream/main`

## Findings

### BF-1
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` - `inspect_spotprice_path` (staleness block around lines 736-745, then continues with `result` around lines 747-772)
2. **Description:** If `get_with_staleness` reports `is_stale`, the code logs and sends a staleness Discord alert but still uses the same cached `result` for `trusted_value` and dispute logic. There is no forced refresh or abort, so monitoring can treat stale oracle/API data as authoritative.
3. **Impact level:** Critical
4. **Points awarded:** 10

### BF-2
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` - `inspect` Discord branch, interaction with `perform_dispute_verification` when immediate refresh cancels a dispute
2. **Description:** When the first (cached) check is disputable but the immediate fresh fetch clears the dispute, `second_trusted_value` stays `None`. The UI falls through to the standard single-check path and formats the alert with `trusted_value` equal to the first/cached value only, so operators never see the fresh value (for example `99.5`) that actually justified canceling the dispute.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-3
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` - `inspect_aggregate_report` (`fetch_value_cached(feed, query_id, logger)`)
2. **Description:** `query_type` is resolved from the query object but is not passed into `fetch_value_cached`, so per-query `check_interval` and staleness behavior from `ConfigWatcher` is ignored for aggregates. TTL falls back to the global `_ttl` snapshot, which can diverge from per-query settings and from single-report inspection.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-4
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` - `inspect_reports` deprecated handling
2. **Description:** For a deprecated query type, the code loops per report and calls `deprecated_query_type_alert` each time. A single batch with many reports can produce many identical Discord alerts, creating noise, possible rate-limit pressure, and reduced signal.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-5
1. **Location/identifier:** `src/layer_values_monitor/telliot_feeds.py` - `fetch_value_cached`
2. **Description:** There is no request coalescing or per-query lock. Concurrent tasks that miss cache can all call `fetch_value` together, defeating rate-limit protection and duplicating work under load.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-6
1. **Location/identifier:** `README.md` / `env.example` vs `src/layer_values_monitor/monitor.py` - `inspect_trbbridge_reports` (`chain_id = int(os.getenv("TRBBRIDGE_CHAIN_ID", "1"))`)
2. **Description:** Docs and `env.example` imply Sepolia-style usage (`11155111`), but the code default if the variable is unset is `1` (mainnet). Operators who omit the env var get a chain ID that does not match documented defaults, risking wrong RPC or contract context.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-7
1. **Location/identifier:** Repo root - `config.toml.example` renamed to `config_example.toml`
2. **Description:** External scripts, CI, or docs that still reference `config.toml.example` will break or copy the wrong file after upgrade.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-8
1. **Location/identifier:** `src/layer_values_monitor/dispute.py` - `is_disputable` percentage branch
2. **Description:** Only `trusted_value is None` is guarded. If `metric` is `percentage` and `trusted_value == 0`, `(reported_value - trusted_value) / trusted_value` raises `ZeroDivisionError`. This path is unchanged in spirit and remains a runtime footgun next to the new `None` guard.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-9
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` + `src/layer_values_monitor/telliot_feeds.py` - config reload vs `initialize_cache_with_config` / `_ttl`
2. **Description:** `initialize_cache_with_config` sets `_price_cache._ttl` once at startup. `ConfigWatcher.reload_config()` can change `[cache]` and intervals later, but the cache's default `_ttl` is not refreshed. Any code path that calls `fetch_value_cached` without `query_type` (for example aggregates) keeps using the old default TTL until restart.
3. **Impact level:** Medium
4. **Points awarded:** 5

### BF-10
1. **Location/identifier:** `pyproject.toml` - `telliot-feeds>=0.4.14` changed to `>=0.4.15`
2. **Description:** Relaxing to a lower-bound-only constraint, while `uv.lock` pins a version, allows future `uv lock --upgrade` or non-lock installs to pull newer telliot-feeds releases without a deliberate review. Behavior of feeds and sources can change out of band.
3. **Impact level:** Low
4. **Points awarded:** 1

### BF-11
1. **Location/identifier:** `src/layer_values_monitor/telliot_feeds.py` - `PriceCache.get_stats`
2. **Description:** `get_stats` reads `_hits`, `_misses`, and `len(self._cache)` without synchronizing with the async lock used elsewhere, so logged cache stats can be internally inconsistent under concurrency. This is benign but misleading operational signal.
3. **Impact level:** Low
4. **Points awarded:** 1

### BF-12
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` `inspect_spotprice_path` + `src/layer_values_monitor/telliot_feeds.py` `PriceCache.get` / `get_with_staleness`
2. **Description:** Each inspection typically calls `cache.get` and then `get_with_staleness`, and both methods bump hit or miss counters. Periodic logs therefore double-count logical lookups and distort hit-rate interpretation.
3. **Impact level:** Low
4. **Points awarded:** 1

### BF-13
1. **Location/identifier:** `src/layer_values_monitor/main.py` - `--check-interval` help text
2. **Description:** Help still refers to `config.toml` as the source of the default while the example file is `config_example.toml` and users are told to copy it to `config.toml`, which can create confusion about which file the string refers to.
3. **Impact level:** Low
4. **Points awarded:** 1

### BF-14
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` - `inspect_evmcall_path` vs `inspect_spotprice_path`
2. **Description:** Staleness detection and `send_staleness_alert` are implemented for SpotPrice only. EVMCall uses the same cached fetch pattern but has no parallel staleness alerting, so operators get asymmetric visibility for similar failure modes such as stuck or old cache.
3. **Impact level:** Low
4. **Points awarded:** 1

### BF-15
1. **Location/identifier:** `src/layer_values_monitor/monitor.py` - `inspect_aggregate_report`
2. **Description:** `get_query` is invoked twice back-to-back with the same `query_data`, creating redundant work and a minor clarity cost.
3. **Impact level:** Low
4. **Points awarded:** 1

## Total Score

**56**
