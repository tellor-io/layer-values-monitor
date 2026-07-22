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

**Advanced (Custom/Backup):**
- `EVM_RPC_URLS_<CHAIN_ID>` - Comma-separated RPC URLs per chain
  - Example: `EVM_RPC_URLS_1="https://ethrpc1.com,https://ethrpc2.com"`
  - Example: `EVM_RPC_URLS_11155111="https://sepolia1.com,https://sepolia2.com"`

### TRB Bridge Monitoring
Required only when monitoring TRBBridge/TRBBridgeV2 query types.
- `TRBBRIDGE_CONTRACT_ADDRESS` - Bridge contract address for TRBBridge
- `TRBBRIDGEV2_CONTRACT_ADDRESS` - Bridge contract address for TRBBridgeV2
- `TRBBRIDGE_CHAIN_ID` - Bridge chain ID, shared by both versions (code default: `1`; set `11155111` for Sepolia)

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
    # Uses global equality defaults

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
- **stdout/journald**: full application logs, including debug records
- **Local text logs**: disabled by default
- **LVM_ENABLE_FILE_LOGS=true**: also writes `terminal_log.log` (INFO and above) and `debug_log.log` (DEBUG and above) in the project folder
- **Rotation**: optional text logs rotate at 10 MB and keep 5 backups per log type
- **CSV Data**: `logs/table_*.csv`

For systemd deployments, use `StandardOutput=journal` and `StandardError=journal` so logs can be managed with `journalctl`.
