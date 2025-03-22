![Unit Tests](https://github.com/tellor-io/layer-values-monitor/actions/workflows/test.yml/badge.svg)
![Ruff](https://github.com/tellor-io/layer-values-monitor/actions/workflows/ruff.yml/badge.svg)

# Layer Values Monitor

### Install uv
```sh
https://docs.astral.sh/uv/#installation
```
### Create virtual environment
```sh
uv venv
# https://docs.astral.sh/uv/reference/cli/#uv-venv
```
### Tests
```sh
uv run pytest
```
### Values monitor
```sh
uv run layer-values-monitor \
--use-custom-config \
binary_path=./layer \
key_name=alice \
keyring_backend=test \
keyring_dir=~/.layer/alice \
payfrom_bond=False
```

### Configuration

The Layer Values Monitor can be configured using either a configuration file or command-line parameters.

#### Global Configuration

The global configurations are set in the command-line and requires setting the alert threshold plus the different categories warning, minor, and major for all three threshold types: percentage, range, and equality.
The configuration file is located in the parent directory at `config.toml`. This is where you can customize setting threshold values for monitoring by specific query ids.

#### Custom Configuration

To use custom configuration settings:

1. **Command-line parameters**: Pass the `--use-custom-config` flag followed by key=value pairs as shown in the example above.

#### Required args for starting the monitor

| Args | Description |
|--------|-------------|
| `binary_path` | Path to the Layer executable |
| `key_name` | Name of the key to use for signing transactions |
| `keyring_backend` | Keyring backend to use (ie os, test) |
| `keyring_dir` | Directory for the keyring |
| `payfrom_bond` | Whether to use the bond for paying transaction fees |

#### Option 1

Set the global threshold for monitoring all the submitted values.
| Args | Description |
|--------|-------------|
| `--global-percentage-alert-threshold` | Percentage alert threshold |
| `--global-percentage-warning-threshold ` | Percentage warning level threshold |
| `--global-percentage-minor-threshold` | Percentage minor level threshold |
| `--global-percentage-major-threshold` | Percentage major level threshold |
| `--global-range-alert-threshold ` | Range alert threshold |
| `--global-range-warning-threshold` | Range warning level threshold |
| `--global-range-minor-threshold` | Range minor level threshold|
| `--global-range-major-threshold` | Range major level threshold |
| `--global-equality-threshold` | Directory for the keyring |

#### Option 2
For only monitoring the config.toml file set the following flag: `--use-custom-config` with the above required args.

#### Option 3
Do both option 1 and 2.  Set the global thresholds without the `--use-custom-config` flag and add custom configurations to the `config.toml`

#### ENV file configs (required)
| Variables | Description |
|-----------|-------------|
| `CHAIN_ID` | Chain ID of the Layer network (ie `layer-testnet`) |
| `URI` | URI of the Layer node to connect to (ie `localhost:26657`) |
| `DISCORD_WEBHOOK_URL_1` | Discord webhook url to recieve to notifications on |

#### Threshold Settings

The configuration file also allows you to set thresholds for monitoring values. These thresholds determine when the monitor should take action.

| Threshold | Description |
|-----------|-------------|
| `metric` | The metric to use for a specific query (percentage, range, equality) |
| `alert_threshold` | the threshold for alerts only |
| `warning_threshold` | Lowest level dispute category threshold |
| `minor_threshold` | Middle level dispute category threshold |
| `major_threshold` | Highest level in  dispute category threshold |

**NOTE** For disputing at minimum the warning category has to be set greater than 0. The thresholds should `float` types. The equality metric is 1.0 for True and 0.0 for False.

#### Example Config File (TOML format)

```toml
[some_random_query_id]
metric = "equality"
alert_threshold = 1.0
warning_threshold = 0.0
minor_threshold = 0.0
major_threshold = 0.0
```