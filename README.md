![Unit Tests](https://github.com/tellor-io/layer-values-monitor/actions/workflows/test.yml/badge.svg)
![Ruff](https://github.com/tellor-io/layer-values-monitor/actions/workflows/ruff.yml/badge.svg)

# Layer Values Monitor

Monitors new_report and aggregate_report events on Layer. Compares values against trusted sources, sends Discord alerts, and can auto-dispute or pause contracts.

**NOTE**: All preset thresholds are arbitrary and should be carefully considered.

## Quick Start

### 1. Install Dependencies
```sh
# Install uv package manager
# https://docs.astral.sh/uv/#installation

# Create virtual environment
uv venv
# https://docs.astral.sh/uv/reference/cli/#uv-venv
```

### 2. Configure
```sh
cp env.example .env
nano .env           # Edit required settings
nano config.toml    # Edit thresholds 
```

### 3. Run the Monitor
```sh
uv run layer-values-monitor
```

## Environment Variables

### Required: Layer Node
- `URI` - Layer node endpoint (e.g., `localhost:26657`)
- `CHAIN_ID` - Layer chain ID (e.g., `layertest-5`)

### Required: Dispute Transactions
These can be set in `.env` or passed as positional CLI arguments.
- `LAYER_BINARY_PATH` - Path to `layerd` binary
- `LAYER_KEY_NAME` - Keyring key name
- `LAYER_KEYRING_BACKEND` - Keyring backend (e.g., `test`)
- `LAYER_KEYRING_DIR` - Keyring directory (e.g., `/home/<USERNAME>/.layer`)

### Alerts
- `DISCORD_WEBHOOK_URL_1` - Primary Discord webhook for alerts
- `DISCORD_WEBHOOK_URL_2`, `DISCORD_WEBHOOK_URL_3` - Optional additional webhooks
- `MONITOR_NAME` - Monitor instance name shown in alerts (default: `LVM`)

### Optional Runtime Settings
- `MAX_TABLE_ROWS` - Max CSV rows before rotation (default: `100000`)
- `MAX_CATCHUP_BLOCKS` - Max blocks to process on reconnect (default: `15`)
- `PAYFROM_BOND` - Pay from bond vs balance (default: `false`)
- `LVM_ENABLE_FILE_LOGS` - Also write local `.log` files in the project folder when set to `true`, `1`, or `yes` (default: disabled)

### EVM RPC Configuration
**Simple (Infura):**
- `INFURA_API_KEY` - Auto-configures mainnet (chain 1) and Sepolia (chain 11155111)

**Recommended (Custom/Backup):**
- `EVM_RPC_URLS` - Comma-separated RPC URLs; applies to the EVM chain implied by `CHAIN_ID`
  (tellor-1 -> chain 1, layertest-5 -> chain 11155111)
  - Example: `EVM_RPC_URLS="https://ethrpc1.com,https://ethrpc2.com"`
- `EVM_RPC_URLS_<chain_id>` - Optional per-chain override; wins over the plain var
  - Example: `EVM_RPC_URLS_11155111="https://sepolia1.com,https://sepolia2.com"`

### TRB Bridge Monitoring
Required only when monitoring TRBBridge/TRBBridgeV2 query types.
- `TRBBRIDGE_CONTRACT_ADDRESS` - Bridge contract address for TRBBridge
- `TRBBRIDGEV2_CONTRACT_ADDRESS` - Bridge contract address for TRBBridgeV2
- `TRBBRIDGE_CHAIN_ID` - Bridge chain ID, shared by both versions (code default: `1`; set `11155111` for Sepolia)

Built-in defaults are selected by the monitored Layer chain (`CHAIN_ID`);
the env vars above are overrides, required only on chains without a built-in default
(e.g. local devnets):
- `tellor-1` -> mainnet TokenBridgeV2 `0x6ec401744008f4B018Ed9A36f76e6629799Ee50E`
  (`TRBBRIDGEV2_CONTRACT_ADDRESS` only; `TRBBRIDGE_CONTRACT_ADDRESS` stays unset unless
  you set it), `TRBBRIDGE_CHAIN_ID=1`
- `layertest-5` -> Sepolia TokenBridge `0x62733e63499a25E35844c91275d4c3bdb159D29d` (v1) and
  TokenBridgeV2 `0x55355157703A44f7516FBB831333317E98944e32`, `TRBBRIDGE_CHAIN_ID=11155111`
  (exact match only — layertest-8 and other testnets do NOT inherit these; set the env vars)

For `tellor-1`, `CHAIN_ID` + `EVM_RPC_URLS` covers TokenBridgeV2. `layertest-5` also
bakes in the Sepolia v1 address. On any other chain the env vars are required. A shared
address (both env vars checksum-equal) is queried as TRBBridgeV2.

Startup gate: every configured bridge RPC (`EVM_RPC_URLS[_<chain>]` / Infura) is probed once at
boot; an endpoint answering a different chain ID than the resolved `TRBBRIDGE_CHAIN_ID` is
FATAL (the monitor refuses to start — a wrong-chain endpoint could otherwise produce wrong
trusted values). A startup RPC outage only warns; runtime retries still apply.

### TRB Bridge Verification Ledger (two-tier)
Every bridge report is journaled to a SQLite ledger (`data/bridge_ledger.db` by default).
Row statuses are exactly three — `good`, `bad`, `unverified` — and nothing is terminal but
good/bad. Both tiers share one verdict helper (`get_bridge_verdict`). Tier 1 reads once
and does not wait: a match is `good`; a zero-struct or a mismatch is left `unverified`
for the reconciler. Tier 2 keeps the confirm read — a zero-struct or a mismatch waits
`BRIDGE_CONFIRM_SECONDS` and re-reads, and that confirm read decides `good` or `bad`.

- **Tier 1** (stream) does not hold the new-report queue for the confirm delay. A match is
  recorded `good` and inspected immediately, with nothing queued. A zero-struct or a mismatch
  is recorded `unverified` ("waiting for the confirm read") with `state_ts` already old enough
  for the next reconciler cycle; no dispute and no Discord alert on that path. A full RPC
  outage records `unverified` + a "NO FUNCTIONAL RPC AVAILABLE" alert. A replay of a row
  already `good` or `bad` is skipped.
- **Tier 2** (reconciler task) runs a cycle at startup, then every `BRIDGE_RECONCILE_INTERVAL`
  seconds: it re-reads every `unverified` row **forever** with the confirm read (no retry cap,
  no expiry — a late `bad` inside the 12h window disputes, one after the window alerts
  "LATE VERDICT"). Dispute latency for a stream mismatch is one reconcile interval plus the
  confirm delay. It also sweeps deposits from the contract's gapless `depositId()` counter
  (no event-log scanning); alerts once per eth deposit whose Layer reporting window closes
  with no report (confirmed against the oracle REST when `LAYER_REST_URL` is set); and
  escalates once per row ~10h in with an "RPCs DOWN — ABOUT TO BE UNDISPUTABLE" alert.
- `BRIDGE_LEDGER_PATH` - Ledger SQLite path (default: `./data/bridge_ledger.db`)
- `BRIDGE_RECONCILE_INTERVAL` - Seconds between reconciler cycles (default: `120`)
- `BRIDGE_CONFIRM_SECONDS` - Confirm re-read delay before a zero/mismatch goes `bad` (default: `60`)
- `BRIDGE_REPORT_WINDOW_BLOCKS` × `BRIDGE_LAYER_BLOCK_SECONDS` - reporting window for the
  missing-report alert (defaults `2000` × `12`; Tellor Layer mainnet needs `BRIDGE_LAYER_BLOCK_SECONDS=3`)
- `LAYER_REST_URL` - Layer LCD/REST base for the oracle double-check before a missing-report alert
- `BRIDGE_MISSING_REPORT_MAX_AGE_HOURS` - age cutoff for the missing-report alert; older
  deposits retire silently so a fresh ledger's history backfill doesn't re-alert deposits
  whose reports simply predate the ledger (e.g. old TRBBridge reports from before the
  transition to TRBBridgeV2) (default: `24`)

Note: bridge **auto-dispute** requires the equality dispute threshold to be enabled
(`warning_threshold = 1.0` in `[queries.trbbridgev2.defaults]`, per LVM threshold semantics —
`0.0` disables disputes; alert-only mode still records `bad`). The example config ships with
this enabled for trbbridgev2; trbbridge and evmcall stay alert-only.

### Saga Guardian (Contract Pausing)
Required only when starting with `--enable-saga-guard`.
- `SAGA_RPC_URLS` - Comma-separated Saga RPC URLs
- `SAGA_PRIVATE_KEY` - Guardian wallet private key
- `SAGA_IMMEDIATE_PAUSE_THRESHOLD` - Power % for immediate pause (default: `0.66666666666`)
- `SAGA_DELAYED_PAUSE_THRESHOLD` - Power % for delayed pause (default: `0.3333333333`)

## Configuration (config.toml)

### Structure
```toml
[global_defaults]
    # Defaults for all queries by metric type
    [global_defaults.percentage]
    alert_threshold = 0.1
    warning_threshold = 0.25
    minor_threshold = 0.99
    major_threshold = 0.0
    pause_threshold = 0.2
    
    [global_defaults.equality]
    alert_threshold = 1.0
    # ...
    
    [global_defaults.range]
    alert_threshold = 100.0
    # ...

[query_types]
    # Define query types and their handlers
    spotprice = { metric = "percentage", description = "Price feeds", handler = "telliot_feeds" }
    trbbridge = { metric = "equality", description = "TRB bridge", handler = "trb_bridge" }
    evmcall = { metric = "equality", description = "EVM calls", handler = "evm_call" }

[queries.spotprice]
    # Override defaults for specific query IDs
    [queries.spotprice.83a7f3d48786ac2667503a61e8c415438ed2922eb86a2906e4ee66d9a2ce4992]
    alert_threshold = 0.1
    datafeed_ca = "0x0cD65ca12F6c9b10254FABC0CC62d273ABbb3d84"  # Saga contract for pausing

[queries.trbbridge]
    [queries.trbbridge.defaults]
    # Uses global equality defaults (alert on mismatch, no disputes)

[queries.trbbridgev2]
    [queries.trbbridgev2.defaults]
    warning_threshold = 1.0  # Auto-dispute double-confirmed mismatches (reconciler)

[queries.evmcall]
    [queries.evmcall.defaults]
    # Uses global equality defaults
```

### Metric Types
- **percentage** - For price feeds (e.g., 0.1 = 10% deviation)
- **equality** - For exact matches (1.0 = any difference triggers)
- **range** - For absolute value differences

## Command Line Options

### Basic Usage
```sh
uv run layer-values-monitor [OPTIONS]
```

You can provide dispute transaction settings through `.env`, or pass them positionally:
```sh
uv run layer-values-monitor /home/<USERNAME>/layerd <KEY_NAME> <KEYRING_BACKEND> /home/<USERNAME>/.layer
```

### Flags
- `--enable-saga-guard` - Enable contract pausing for aggregate reports
- `--check-interval <SECONDS>` - Override the trusted value cache/check interval from `config.toml`

## Common Configurations

### Monitor Only (No Disputes)
```sh
uv run layer-values-monitor
```
Set all dispute thresholds to `0.0` in config.toml.

### Auto-Dispute with Custom Thresholds
```sh
uv run layer-values-monitor
```
Configure thresholds per query in config.toml.

### Saga Guardian with Contract Pausing
```sh
uv run layer-values-monitor --enable-saga-guard
```
Requires `SAGA_RPC_URLS` and `SAGA_PRIVATE_KEY` in .env.

## Saga Guardian Details

Pauses datafeed contracts when aggregate reports are incorrect.

### Requirements
- Guardian role on target contracts
- `SAGA_RPC_URLS` and `SAGA_PRIVATE_KEY` in .env
- `--enable-saga-guard` flag
- `datafeed_ca` configured for each query in config.toml

### Power-Based Logic
- **Immediate pause**: Triggered when bad aggregate report power > `SAGA_IMMEDIATE_PAUSE_THRESHOLD` (default `0.66666666666`)
- **Delayed pause**: Triggered when bad aggregate report power > `SAGA_DELAYED_PAUSE_THRESHOLD` (default `0.3333333333`)

Power calculated as % of total non-jailed reporter power.

## Development

### Run Tests
```sh
uv run pytest -v
```

### Linting
```sh
uv run ruff check
uv run ruff format
```

### Logs
Runtime logs are written to standard output so service managers such as journald can capture them.
- **stdout/journald**: operational logs at `LVM_JOURNAL_LOG_LEVEL` and above (default: `INFO`)
- **Normal operation summaries**: per-block report details are debug-only; journald gets compact summaries every `LVM_OPERATIONAL_SUMMARY_INTERVAL_SECONDS` seconds (default: `300`)
- **Warnings/errors/failures**: alerts, stale cache warnings, unsupported queries, dispute failures, and exceptions continue to appear in journald
- **Local text logs**: disabled by default
- **LVM_ENABLE_FILE_LOGS=true**: also writes `terminal_log.log` (INFO and above) and `debug_log.log` (`LVM_DEBUG_FILE_LOG_LEVEL`, default `DEBUG`) in the project folder
- **Rotation**: optional text logs rotate hourly and keep 24 hourly backups per log type, plus the active log
- **CSV Data**: `logs/table_*.csv`

For systemd deployments, use `StandardOutput=journal` and `StandardError=journal` so logs can be managed with `journalctl`.
