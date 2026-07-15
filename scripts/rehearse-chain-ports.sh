#!/usr/bin/env bash
# Measurement-only rehearsal for the csv-chain-ports contract seam.
# This script never moves source, creates repositories, or publishes artifacts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
cargo check --locked -p csv-chain-ports
cargo test --locked -p csv-chain-ports -p csv-runtime
cargo package --locked --allow-dirty --list -p csv-chain-ports >/dev/null
scripts/check-core-api.sh
echo "csv-chain-ports rehearsal passed: packageable, runtime-consumable, API-snapshot stable."
