#!/usr/bin/env bash
# Test workspace layers independently; no testnet credentials are used.
set -euo pipefail
group="${1:?layer group required}"
case "$group" in
  core) packages=(csv-algebra csv-wire csv-hash csv-protocol csv-verifier) ;;
  runtime) packages=(csv-admission csv-chain-ports csv-coordinator csv-storage csv-observability csv-runtime csv-sdk) ;;
  adapters) packages=(csv-adapter-factory csv-bitcoin csv-ethereum csv-solana csv-sui csv-aptos csv-celestia) ;;
  tools) packages=(csv-cli csv-wallet csv-keys csv-store csv-p2p csv-examples) ;;
  *) echo "unknown layer group: $group" >&2; exit 2 ;;
esac
args=()
for package in "${packages[@]}"; do args+=(-p "$package"); done
CXXFLAGS="-include cstdint" cargo test --locked "${args[@]}"
