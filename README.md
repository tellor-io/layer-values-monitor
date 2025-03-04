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