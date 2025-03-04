
build:
    uv build

publish:
    uv publish

local-devnet:
    if command -v local-ic > /dev/null; then \
        echo "Starting local chain"; \
        ICTEST_HOME=. local-ic start layer.json; \
    else \
        echo "local-ic binary not found. Consider installing local-ic: https://github.com/strangelove-ventures/interchaintest/blob/main/local-interchain/README.md"; \
    fi