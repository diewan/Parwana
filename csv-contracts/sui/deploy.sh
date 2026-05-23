#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
sui client publish --gas-budget "${SUI_GAS_BUDGET:-100000000}"
