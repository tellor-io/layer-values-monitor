![Unit Tests](https://github.com/tellor-io/layer-values-monitor/actions/workflows/test.yml/badge.svg)
![Ruff](https://github.com/tellor-io/layer-values-monitor/actions/workflows/ruff.yml/badge.svg)

# Layer Values Monitor

A monitoring system that listens to new_report and aggregate_report events on Layer. New_report values are compared aginst trusted values and can be automatically disputed/alerted about through a discord webhook. Aggregate_report values are compared against trusted values and the related data feed contract can be paused.

**NOTE**: All preset thresholds are arbitrary and should be carefully considered.
## Quick Start

### 1. Install Dependencies
# Install uv package manager
```sh
https://docs.astral.sh/uv/#installation
```

# Create and activate virtual environment
```sh
uv venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows
# https://docs.astral.sh/uv/reference/cli/#uv-venv
```

### 2. Configure Environment
```sh
# Copy example environment file
cp env.example .env

# Edit .env file with your settings
nano .env

# OPTIONAL BUT RECOMMENDED: edit all config thresholds
nano config.toml
```

### 3. Run the Monitor
```sh
# Basic monitoring 
uv run layer-values-monitor --use-custom-config
```

## Env Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `URI` | Layer node WebSocket endpoint | `localhost:26657` |
| `CHAIN_ID` | Layer chain identifier | `layer-testnet-3` |


### Optional (Recommended) Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LAYER_BINARY_PATH` | Path to Layer executable | `/usr/local/bin/layerd` |
| `LAYER_KEY_NAME` | Key name for transactions | `alice` |
| `LAYER_KEYRING_BACKEND` | Keyring backend type | `test` |
| `LAYER_KEYRING_DIR` | Keyring directory | `~/.layer` |
| `PAYFROM_BOND` | Pay dispute fees from bond | `false` |
| | | |
| `DISCORD_WEBHOOK_URL_1` | Discord notifications webhook 1 | _(none)_ |
| `MAX_TABLE_ROWS` | Maximum rows in reports tables | `1000000` |
| | | |
| `TRBBRIDGE_CONTRACT_ADDRESS` | TRB Bridge contract address | _(none)_ |
| `TRBBRIDGE_CHAIN_ID` | Chain ID for bridge contract (default sepolia) | `11155111` |
| `ETHEREUM_RPC_URL` | Ethereum RPC endpoint (for TRB Bridge) | _(none)_ |
| | | |
| `SAGA_EVM_RPC_URL` | Saga EVM RPC endpoint | _(none)_ |
| `SAGA_PRIVATE_KEY` | Guardian private key | _(none)_ |
| `CG_API_KEY` | CoinGecko API key for price data | _(none)_ |
| `CMC_API_KEY` | CoinMarketCap API key for price data | _(none)_ |

## Command Line Options

### Basic Usage
```sh
uv run layer-values-monitor [options]
```

### Available Flags

| Flag | Description |
|------|-------------|
| `--use-custom-config` | Use config.toml for query-specific settings |
| `--enable-saga-guard` | Enable aggregate report and Saga contract guarding |
| `--payfrom-bond` | Pay dispute fees from reporter bond, defaults to false |

### Global Thresholds

Set global dispute thresholds for all queries.

**NOTE:** If you do not want to auto dispute a certain queryId or queryType, set all threshold values to 0 for it in `config.toml`.

| Flag | Description | Default |
|------|-------------|---------|
| `--global-percentage-alert-threshold` | Percentage threshold for alerts | `0.1` |
| `--global-percentage-warning-threshold` | Warning dispute threshold | `0.0` |
| `--global-percentage-minor-threshold` | Minor dispute threshold | `0.0` |
| `--global-percentage-major-threshold` | Major dispute threshold | `0.0` |
| `--global-range-...-threshold` | Range-based thresholds | `0.0` |
| `--global-equality-...-threshold` | Equality thresholds | `0.0` |

## Configuration Strategies

### Strategy 1 (Recommended): Fully configure .env and config.toml
Set all configuration in your `.env` and `config.toml` files:
```sh
uv run layer-values-monitor --use-custom-config
```

### Strategy 2: Custom config, no optional env fields
Use custom thresholds and more command line parameters:
```sh
uv run layer-values-monitor /path/to/layerd alice test ~/.layer --payfrom-bond --use-custom-config
```

### Strategy 3: Minimum .env setting, set thresholds in start command
Set everything via command line:
```sh
uv run layer-values-monitor \
  /path/to/layerd \
  alice \
  test \
  ~/.layer/alice \
  --payfrom-bond \
  --global-percentage-alert-threshold 0.1 \
  --global-percentage-warning-threshold 0.2 \
  --global-percentage-minor-threshold 0.4 \
  --global-percentage-major-threshold 0.6 \
  --global-range-alert-threshold 1.0 \
  --global-range-warning-threshold 1.0 \
  --global-range-minor-threshold 0 \
  --global-range-major-threshold 0 \
  --global-equality-alert-threshold 1.0 \
  --global-equality-warning-threshold 1.0 \
  --global-equality-minor-threshold 0 \
  --global-equality-major-threshold 0
```

### Strategy 4: Global + Custom
Combine global thresholds with query-specific overrides:
```sh
uv run layer-values-monitor \
  --global-percentage-warning-threshold 0.05 \
  --use-custom-config
```

## Query-Specific Configuration (config.toml)

```toml
# Example: BTC/USD price feed monitoring
[a6f013ee236804827b77696d350e9f0ac3e879328f2a3021d473a0b778ad78ac]
metric = "percentage"
alert_threshold = 0.05     # 5% deviation for alerts
warning_threshold = 0.10   # 10% for warning disputes
minor_threshold = 0.15     # 15% for minor disputes  
major_threshold = 0.25     # 25% for major disputes
pause_threshold = 0.50     # 50% triggers contract pause if --enable-saga-guard used
contract_address = "0x9fe237b245466A5f088AfE808b27c1305E3027BC" # saga contract address

# Example: Exact equality check
[trbbridge]
metric = "equality"
alert_threshold = 1.0 # any difference triggers alert
warning_threshold = 1.0 # any difference triggers warning dispute
minor_threshold = 0.0
major_threshold = 0.0
```


## Saga Guard

Enable automatic contract pausing when aggregate report values are incorrect. Threshold for incorrect can be set in config.toml. Only relevant for contract guardians.

### Requirements
- Guardian permissions on target contracts
- Valid `SAGA_EVM_RPC_URL` and `SAGA_PRIVATE_KEY`
- Use `--enable-saga-guard` flag in start command

### How It Works
1. Listen for aggregate report events
2. Compare aggregate value against trusted data sources
3. If `pause_threshold` exceeded, pause configured contracts

## Examples

### Basic Report Monitoring
```sh
# New report monitoring with 5% auto alert threshold
# no auto disputes on spot prices
uv run layer-values-monitor \
  --global-percentage-alert-threshold 0.1 \
  --global-percentage-warning-threshold 0.0 \
  --global-percentage-minor-threshold 0.0 \
  --global-percentage-major-threshold 0.0 \
```

### Production Setup with Saga Guard
```sh
# New report and aggregate report monitoring using config thresholds
uv run layer-values-monitor \
  --enable-saga-guard \
  --use-custom-config
```

## Development

### Run Tests
```sh
uv run pytest -v -s
```

### Build Package
```sh
uv build
```

### Linting
```sh
uv run ruff check
uv run ruff format
```

### Logs

- **Console**: INFO level and above
- **File**: All logs saved to `monitor_log.log`  
- **CSV Data**: Report details saved to `logs/table_*.csv`