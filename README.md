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

### Required
- `URI` - Layer node endpoint (e.g., `localhost:26657`)
- `CHAIN_ID` - Layer chain ID (e.g., `layertest-4`)
- `MONITOR_NAME` - Monitor instance name
- `DISCORD_WEBHOOK_URL_1` - Discord webhook for alerts
- `MAX_TABLE_ROWS` - Max CSV rows before rotation (default: `1000000`)

### Dispute Configuration
- `LAYER_BINARY_PATH` - Path to layerd binary
- `LAYER_KEY_NAME` - Keyring key name
- `LAYER_KEYRING_BACKEND` - Keyring backend (e.g., `test`)
- `LAYER_KEYRING_DIR` - Keyring directory (e.g., `~/.layer`)
- `PAYFROM_BOND` - Pay from bond vs balance (default: `false`)

### EVM RPC Configuration
**Simple (Infura):**
- `INFURA_API_KEY` - Auto-configures mainnet (chain 1) and Sepolia (chain 11155111)

**Advanced (Custom/Backup):**
- `EVM_RPC_URLS_<CHAIN_ID>` - Comma-separated RPC URLs per chain
  - Example: `EVM_RPC_URLS_1="https://ethrpc1.com,https://ethrpc2.com"`
  - Example: `EVM_RPC_URLS_137="https://polygonrpc1.com"`

### TRB Bridge Monitoring
- `TRBBRIDGE_CONTRACT_ADDRESS` - Bridge contract address
- `TRBBRIDGE_CHAIN_ID` - Bridge chain ID (default: `11155111`)

### Saga Guardian (Contract Pausing)
- `SAGA_RPC_URLS` - Comma-separated Saga RPC URLs
- `SAGA_PRIVATE_KEY` - Guardian wallet private key
- `SAGA_IMMEDIATE_PAUSE_THRESHOLD` - Power % for immediate pause (default: `0.66`)
- `SAGA_DELAYED_PAUSE_THRESHOLD` - Power % for delayed pause (default: `0.33`)

### Other
- `MAX_CATCHUP_BLOCKS` - Max blocks to process on reconnect (default: `15`)
- `DISCORD_WEBHOOK_URL_2`, `DISCORD_WEBHOOK_URL_3` - Additional webhooks

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

### Flags
- `--enable-saga-guard` - Enable contract pausing for aggregate reports

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
- **Immediate pause**: Triggered when bad aggregate report power > `SAGA_IMMEDIATE_PAUSE_THRESHOLD` (default 66%)
- **Delayed pause**: Triggered when bad aggregate report power > `SAGA_DELAYED_PAUSE_THRESHOLD` (default 33%)

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
All log files will rotate to new file after they recach 52mb
- **Console**: INFO and above, captured in terminal_log.log
- **File**: full logs are in debug_log.log
- **CSV Data**: `logs/table_*.csv`